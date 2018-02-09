/*
 * Copyright (c) 2015 - 2017, Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "spi.h"
#include "nrfx_spi.h"

#define SYS_LOG_DOMAIN "SPI NRF5"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_SPI_LEVEL
#include <logging/sys_log.h>

#include "spi_context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPI_NRF5_MAX_SLAVES_ON_BUS (4)

typedef void (*irq_cfg_func_t)(void);

/** Configuration data */
struct spi_nrf5_cfg {
	nrfx_spi_t spi;
	irq_cfg_func_t irq_cfg_func;
	struct {
		u8_t sck;
		u8_t mosi;
		u8_t miso;
		/* Pin numbers of up to 4 slave devices */
		u8_t ss[SPI_NRF5_MAX_SLAVES_ON_BUS];
	} psel;
	u8_t orc;
};

/** Driver data */
struct spi_nrf5_data {
	struct spi_context ctx;
	u16_t transfer_len;
	bool busy;
};

#define DEV_CFG(spi_cfg) ((const struct spi_nrf5_cfg * const) \
					(spi_cfg->dev)->config->config_info)
#define DEV_DATA(spi_cfg) ((struct spi_nrf5_data * const) \
					(spi_cfg->dev)->driver_data)

static inline nrfx_spi_frequency_t spi_freq_to_nrfx_freq(u32_t frequency)
{
	switch (frequency) {
	case 125000:
		return NRFX_SPI_FREQ_125K;
	case 250000:
		return NRFX_SPI_FREQ_250K;
	case 500000:
		return NRFX_SPI_FREQ_500K;
	case 1000000:
		return NRFX_SPI_FREQ_1M;
	case 2000000:
		return NRFX_SPI_FREQ_2M;
	case 4000000:
		return NRFX_SPI_FREQ_4M;
	case 8000000:
		return NRFX_SPI_FREQ_8M;
	default:
		SYS_LOG_WRN("Unsupported frequency, setting 125 kbps");
		return NRFX_SPI_FREQ_125K;
	}
}

static inline nrfx_spi_mode_t spi_operation_to_nrfx_mode(u16_t operation)
{
	if (SPI_MODE_GET(operation) & SPI_MODE_CPOL) {
		if (SPI_MODE_GET(operation) & SPI_MODE_CPHA) {
			return NRFX_SPI_MODE_3;
		} else {
			return NRFX_SPI_MODE_2;
		}
	} else {
		if (SPI_MODE_GET(operation) & SPI_MODE_CPHA) {
			return NRFX_SPI_MODE_1;
		} else {
			return NRFX_SPI_MODE_0;
		}
	}
}

static inline
nrfx_spi_bit_order_t spi_operation_to_nrfx_bit_order(u16_t operation)
{
	if (operation & SPI_TRANSFER_LSB) {
		return NRFX_SPI_BIT_ORDER_LSB_FIRST;
	} else {
		return NRFX_SPI_BIT_ORDER_MSB_FIRST;
	}
}

static inline int set_nrfx_spi_config(nrfx_spi_config_t *nrfx_spi_cfg,
				      const struct spi_config *spi_cfg)
{
	const struct spi_nrf5_cfg *dev_cfg = DEV_CFG(spi_cfg);
	u8_t slave = spi_cfg->slave;

	nrfx_spi_cfg->sck_pin  = dev_cfg->psel.sck;
	nrfx_spi_cfg->mosi_pin = dev_cfg->psel.mosi;
	nrfx_spi_cfg->miso_pin = dev_cfg->psel.miso;

	if (spi_cfg->cs) {
		nrfx_spi_cfg->ss_pin = NRFX_SPI_PIN_NOT_USED;
	} else {
		if (slave < SPI_NRF5_MAX_SLAVES_ON_BUS) {
			if (dev_cfg->psel.ss[slave] ==
			    CONFIG_SPI_NRF5_SS_UNUSED_PIN) {
				return -1;
			}

			nrfx_spi_cfg->ss_pin = dev_cfg->psel.ss[slave];
		} else {
			return -1;
		}
	}

	/* IRQ priority is set via IRQ_CONNECT */
	nrfx_spi_cfg->irq_priority = 0;
	nrfx_spi_cfg->orc = dev_cfg->orc;
	nrfx_spi_cfg->frequency = spi_freq_to_nrfx_freq(spi_cfg->frequency);
	nrfx_spi_cfg->mode = spi_operation_to_nrfx_mode(spi_cfg->operation);
	nrfx_spi_cfg->bit_order = spi_operation_to_nrfx_bit_order(
							spi_cfg->operation);

	return 0;
}

static void spi_nrf5_nrfx_evt_handler(const nrfx_spi_evt_t *p_event,
				      void *p_context);

static int spi_nrf5_configure(const struct spi_config *spi_cfg)
{
	const struct spi_nrf5_cfg *dev_cfg = DEV_CFG(spi_cfg);
	struct spi_nrf5_data *dev_data = DEV_DATA(spi_cfg);

	SYS_LOG_DBG("%p (prev %p)", spi_cfg, dev_data->ctx.config);

	if (spi_context_configured(&dev_data->ctx, spi_cfg)) {
		/* Nothing to do */
		return 0;
	}

	if (spi_cfg->operation & SPI_OP_MODE_SLAVE) {
		SYS_LOG_ERR("SPI peripheral does not support slave mode");
		return -EINVAL;
	}

	if ((spi_cfg->operation & SPI_LINES_MASK) != SPI_LINES_SINGLE) {
		SYS_LOG_ERR("SPI peripheral does not support dual, quad, "
			    "or octal mode");
		return -EINVAL;
	}

	if (SPI_WORD_SIZE_GET(spi_cfg->operation) != 8) {
		SYS_LOG_ERR("Nordic SPI does not support word size other "
			    "than 8 bits");
		return -EINVAL;
	}

	nrfx_err_t err;
	nrfx_spi_config_t nrfx_spi_cfg;

	if (dev_data->ctx.config) {
		nrfx_spi_uninit(&dev_cfg->spi);
		dev_data->ctx.config = NULL;
	}

	if (set_nrfx_spi_config(&nrfx_spi_cfg, spi_cfg)) {
		return -EINVAL;
	}

	err = nrfx_spi_init(&dev_cfg->spi,
			    &nrfx_spi_cfg,
			    spi_nrf5_nrfx_evt_handler,
			    spi_cfg->dev);

	if (err != NRFX_SUCCESS) {
		SYS_LOG_ERR("Error %d while initializing nrfx SPI", err);
		return -1;
	}

	dev_data->ctx.config = spi_cfg;

	spi_context_cs_configure(&dev_data->ctx);

	return 0;
}

static inline void set_buffers_len_for_nrfx(nrfx_spi_xfer_desc_t *xfer_desc,
					    u32_t len)
{
	if (xfer_desc->p_tx_buffer) {
		xfer_desc->tx_length = len;
	} else {
		xfer_desc->tx_length = 0;
	}

	if (xfer_desc->p_rx_buffer) {
		xfer_desc->rx_length = len;
	} else {
		xfer_desc->rx_length = 0;
	}
}

static void spi_nrf5_transfer_next_packet(struct device *dev)
{
	const struct spi_nrf5_cfg *dev_cfg = dev->config->config_info;
	struct spi_nrf5_data *dev_data = dev->driver_data;
	int status = 0;

	dev_data->transfer_len = spi_context_longest_current_buf(
							&dev_data->ctx);

	if (dev_data->transfer_len > 0) {
		nrfx_spi_xfer_desc_t xfer_desc;
		xfer_desc.p_tx_buffer = dev_data->ctx.tx_buf;
		xfer_desc.p_rx_buffer = dev_data->ctx.rx_buf;
		set_buffers_len_for_nrfx(&xfer_desc, dev_data->transfer_len);
		status = nrfx_spi_xfer(&dev_cfg->spi, &xfer_desc, 0);

		if ((nrfx_err_t)status == NRFX_SUCCESS) {
			return;
		}

		status = -EIO;
	}

	spi_context_cs_control(&dev_data->ctx, false);

	SYS_LOG_DBG("SPI transaction completed %s error",
		    status ? "with" : "without");

	spi_context_complete(&dev_data->ctx, status);
	dev_data->busy = false;
}

static int transceive(const struct spi_config *spi_cfg,
		      const struct spi_buf_set *tx_bufs,
		      const struct spi_buf_set *rx_bufs,
		      bool asynchronous,
		      struct k_poll_signal *signal)
{
	struct spi_nrf5_data *dev_data = DEV_DATA(spi_cfg);
	int ret;

	spi_context_lock(&dev_data->ctx, asynchronous, signal);

	ret = spi_nrf5_configure(spi_cfg);
	if (ret) {
		goto out;
	}

	dev_data->busy = true;

	/* Set buffers info */
	spi_context_buffers_setup(&dev_data->ctx, tx_bufs, rx_bufs, 1);

	spi_context_cs_control(&dev_data->ctx, true);

	spi_nrf5_transfer_next_packet(spi_cfg->dev);

	ret = spi_context_wait_for_completion(&dev_data->ctx);

out:
	spi_context_release(&dev_data->ctx, ret);

	return ret;
}

static int spi_nrf5_transceive(const struct spi_config *spi_cfg,
			       const struct spi_buf_set *tx_bufs,
			       const struct spi_buf_set *rx_bufs)
{
	return transceive(spi_cfg, tx_bufs, rx_bufs, false, NULL);
}

#ifdef CONFIG_SPI_ASYNC
static int spi_nrf5_transceive_async(const struct spi_config *spi_cfg,
				     const struct spi_buf_set *tx_bufs,
				     const struct spi_buf_set *rx_bufs,
				     struct k_poll_signal *async)
{
	return transceive(spi_cfg, tx_bufs, rx_bufs, true, async);
}
#endif /* CONFIG_SPI_ASYNC */

static int spi_nrf5_release(const struct spi_config *spi_cfg)
{
	struct spi_nrf5_data *dev_data = DEV_DATA(spi_cfg);

	if (!spi_context_configured(&dev_data->ctx, spi_cfg)) {
		return -EINVAL;
	}

	if (dev_data->busy) {
		return -EBUSY;
	}

	spi_context_unlock_unconditionally(&dev_data->ctx);

	return 0;
}

static const struct spi_driver_api spi_nrf5_drv_api = {
	.transceive = spi_nrf5_transceive,
#ifdef CONFIG_SPI_ASYNC
	.transceive_async = spi_nrf5_transceive_async,
#endif
	.release = spi_nrf5_release,
};

static int spi_nrf5_init(struct device *dev)
{
	const struct spi_nrf5_cfg *dev_cfg = dev->config->config_info;
	struct spi_nrf5_data *dev_data = dev->driver_data;

	dev_cfg->irq_cfg_func();

	spi_context_unlock_unconditionally(&dev_data->ctx);

	return 0;
}

static void nrfx_spi_event_done_handler(struct device *dev)
{
	struct spi_nrf5_data *dev_data = dev->driver_data;

	spi_context_update_tx(&dev_data->ctx, 1, dev_data->transfer_len);
	spi_context_update_rx(&dev_data->ctx, 1, dev_data->transfer_len);

	spi_nrf5_transfer_next_packet(dev);
}

static void spi_nrf5_isr(void *irq_handler)
{
	((nrfx_irq_handler_t)irq_handler)();
}

static void spi_nrf5_nrfx_evt_handler(const nrfx_spi_evt_t *p_event,
				      void *p_context)
{
	struct device *dev = p_context;

	switch (p_event->type) {
	case NRFX_SPI_EVENT_DONE:
		nrfx_spi_event_done_handler(dev);
		break;
	default:
		SYS_LOG_ERR("Unknown event %d", p_event->type);
		break;
	}
}

#ifdef CONFIG_SPI_0_NRF5
DEVICE_DECLARE(spi_nrf5_0);

static void spi_nrf5_irq_cfg_func_0(void)
{
	IRQ_CONNECT(SPI0_TWI0_IRQn,
		    CONFIG_SPI_0_IRQ_PRI,
		    spi_nrf5_isr,
		    nrfx_spi_0_irq_handler,
		    0);
}

static const struct spi_nrf5_cfg spi_nrf5_cfg_0 = {
	.spi = NRFX_SPI_INSTANCE(0),
	.irq_cfg_func = spi_nrf5_irq_cfg_func_0,
	.psel = {
		.sck  = CONFIG_SPI_0_NRF5_GPIO_SCK_PIN,
		.mosi = CONFIG_SPI_0_NRF5_GPIO_MOSI_PIN,
		.miso = CONFIG_SPI_0_NRF5_GPIO_MISO_PIN,
		.ss = { CONFIG_SPI_0_NRF5_GPIO_SS_PIN_0,
			CONFIG_SPI_0_NRF5_GPIO_SS_PIN_1,
			CONFIG_SPI_0_NRF5_GPIO_SS_PIN_2,
			CONFIG_SPI_0_NRF5_GPIO_SS_PIN_3 },
	},
	.orc = CONFIG_SPI_0_NRF5_ORC
};

static struct spi_nrf5_data spi_nrf5_data_0 = {
	SPI_CONTEXT_INIT_LOCK(spi_nrf5_data_0, ctx),
	SPI_CONTEXT_INIT_SYNC(spi_nrf5_data_0, ctx),
	.busy = false,
};

DEVICE_AND_API_INIT(spi_nrf5_0, CONFIG_SPI_0_NAME, spi_nrf5_init,
		    &spi_nrf5_data_0, &spi_nrf5_cfg_0,
		    POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &spi_nrf5_drv_api);
#endif /* CONFIG_SPI_0_NRF5 */

#ifdef CONFIG_SPI_1_NRF5
DEVICE_DECLARE(spi_nrf5_1);

static void spi_nrf5_irq_cfg_func_1(void)
{
	IRQ_CONNECT(SPI1_TWI1_IRQn,
		    CONFIG_SPI_1_IRQ_PRI,
		    spi_nrf5_isr,
		    nrfx_spi_1_irq_handler,
		    0);
}

static const struct spi_nrf5_cfg spi_nrf5_cfg_1 = {
	.spi = NRFX_SPI_INSTANCE(1),
	.irq_cfg_func = spi_nrf5_irq_cfg_func_1,
	.psel = {
		.sck  = CONFIG_SPI_1_NRF5_GPIO_SCK_PIN,
		.mosi = CONFIG_SPI_1_NRF5_GPIO_MOSI_PIN,
		.miso = CONFIG_SPI_1_NRF5_GPIO_MISO_PIN,
		.ss = { CONFIG_SPI_1_NRF5_GPIO_SS_PIN_0,
			CONFIG_SPI_1_NRF5_GPIO_SS_PIN_1,
			CONFIG_SPI_1_NRF5_GPIO_SS_PIN_2,
			CONFIG_SPI_1_NRF5_GPIO_SS_PIN_3 },
	},
	.orc = CONFIG_SPI_1_NRF5_ORC
};

static struct spi_nrf5_data spi_nrf5_data_1 = {
	SPI_CONTEXT_INIT_LOCK(spi_nrf5_data_1, ctx),
	SPI_CONTEXT_INIT_SYNC(spi_nrf5_data_1, ctx),
	.busy = false,
};

DEVICE_AND_API_INIT(spi_nrf5_1, CONFIG_SPI_1_NAME, spi_nrf5_init,
		    &spi_nrf5_data_1, &spi_nrf5_cfg_1,
		    POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &spi_nrf5_drv_api);
#endif /* CONFIG_SPI_1_NRF5 */

#ifdef CONFIG_SPI_2_NRF5
DEVICE_DECLARE(spi_nrf5_2);

static void spi_nrf5_irq_cfg_func_2(void)
{
	IRQ_CONNECT(SPIM2_SPIS2_SPI2_IRQn,
		    CONFIG_SPI_2_IRQ_PRI,
		    spi_nrf5_isr,
		    nrfx_spi_2_irq_handler,
		    0);
}

static const struct spi_nrf5_cfg spi_nrf5_cfg_2 = {
	.spi = NRFX_SPI_INSTANCE(2),
	.irq_cfg_func = spi_nrf5_irq_cfg_func_2,
	.psel = {
		.sck  = CONFIG_SPI_2_NRF5_GPIO_SCK_PIN,
		.mosi = CONFIG_SPI_2_NRF5_GPIO_MOSI_PIN,
		.miso = CONFIG_SPI_2_NRF5_GPIO_MISO_PIN,
		.ss = { CONFIG_SPI_2_NRF5_GPIO_SS_PIN_0,
			CONFIG_SPI_2_NRF5_GPIO_SS_PIN_1,
			CONFIG_SPI_2_NRF5_GPIO_SS_PIN_2,
			CONFIG_SPI_2_NRF5_GPIO_SS_PIN_3 },
	},
	.orc = CONFIG_SPI_2_NRF5_ORC
};

static struct spi_nrf5_data spi_nrf5_data_2 = {
	SPI_CONTEXT_INIT_LOCK(spi_nrf5_data_2, ctx),
	SPI_CONTEXT_INIT_SYNC(spi_nrf5_data_2, ctx),
	.busy = false,
};

DEVICE_AND_API_INIT(spi_nrf5_2, CONFIG_SPI_2_NAME, spi_nrf5_init,
		    &spi_nrf5_data_2, &spi_nrf5_cfg_2,
		    POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &spi_nrf5_drv_api);
#endif /* CONFIG_SPI_2_NRF5 */

#ifdef __cplusplus
}
#endif
