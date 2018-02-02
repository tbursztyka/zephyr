/*
 * Copyright (c) 2017 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL CONFIG_SYS_LOG_SPI_LEVEL
#include <logging/sys_log.h>

#include "spi_context.h"
#include <device.h>
#include <errno.h>
#include <init.h>
#include <misc/__assert.h>
#include <soc.h>
#include <spi.h>

#if defined(CONFIG_SPI_LEGACY_API)
#error "This driver does not support the SPI legacy API."
#endif

/* Device constant configuration parameters */
struct spi_sam0_config {
	SercomSpi *regs;
	u32_t ctrla;
	u32_t pm_apbcmask;
	u16_t gclk_clkctrl_id;
	struct soc_gpio_pin pin_miso;
	struct soc_gpio_pin pin_mosi;
	struct soc_gpio_pin pin_sck;
};

/* Device run time data */
struct spi_sam0_data {
	struct spi_context ctx;
};

static void wait_synchronization(SercomSpi *regs)
{
#if defined(SERCOM_SPI_SYNCBUSY_MASK)
	/* SYNCBUSY is a register */
	while ((regs->SYNCBUSY.reg & SERCOM_SPI_SYNCBUSY_MASK) != 0) {
	}
#elif defined(SERCOM_SPI_STATUS_SYNCBUSY)
	/* SYNCBUSY is a bit */
	while ((regs->STATUS.reg & SERCOM_SPI_STATUS_SYNCBUSY) != 0) {
	}
#else
#error Unsupported device
#endif
}

static int spi_sam0_configure(const struct spi_config *config)
{
	const struct spi_sam0_config *cfg = config->dev->config->config_info;
	SercomSpi *regs = cfg->regs;
	SERCOM_SPI_CTRLA_Type ctrla = {.reg = 0};
	SERCOM_SPI_CTRLB_Type ctrlb = {.reg = 0};
	int div;

	if (SPI_OP_MODE_GET(config->operation) != SPI_OP_MODE_MASTER) {
		/* Slave mode is not implemented. */
		return -ENOTSUP;
	}

	ctrla.bit.MODE = SERCOM_SPI_CTRLA_MODE_SPI_MASTER_Val;

	if ((config->operation & SPI_TRANSFER_LSB) != 0) {
		ctrla.bit.DORD = 1;
	}

	if ((config->operation & SPI_MODE_CPOL) != 0) {
		ctrla.bit.CPOL = 1;
	}

	if ((config->operation & SPI_MODE_CPHA) != 0) {
		ctrla.bit.CPHA = 1;
	}

	/* MOSI on PAD2, SCK on PAD3 */
	ctrla.bit.DOPO = 1;

	if ((config->operation & SPI_MODE_LOOP) != 0) {
		/* Put MISO on the same pin as MOSI */
		ctrla.bit.DIPO = 2;
	} else {
		ctrla.bit.DIPO = 0;
	}

	ctrla.bit.ENABLE = 1;
	ctrlb.bit.RXEN = 1;

	if (SPI_WORD_SIZE_GET(config->operation) != 8) {
		return -ENOTSUP;
	}

	/* 8 bits per transfer */
	ctrlb.bit.CHSIZE = 0;

	/* Use the requested or next higest possible frequency */
	div = (SOC_ATMEL_SAM0_GCLK0_FREQ_HZ / config->frequency) / 2 - 1;
	div = max(0, min(UINT8_MAX, div));

	/* Update the configuration only if it has changed */
	if (regs->CTRLA.reg != ctrla.reg || regs->CTRLB.reg != ctrlb.reg ||
	    regs->BAUD.reg != div) {
		regs->CTRLA.bit.ENABLE = 0;
		wait_synchronization(regs);

		regs->CTRLB = ctrlb;
		wait_synchronization(regs);
		regs->BAUD.reg = div;
		wait_synchronization(regs);
		regs->CTRLA = ctrla;
		wait_synchronization(regs);
	}

	return 0;
}

static bool spi_sam0_transfer_ongoing(struct spi_sam0_data *data)
{
	return spi_context_tx_on(&data->ctx) || spi_context_rx_on(&data->ctx);
}

static void spi_sam0_shift_master(SercomSpi *regs, struct spi_sam0_data *data)
{
	u8_t tx;
	u8_t rx;

	if (spi_context_tx_on(&data->ctx)) {
		tx = *(u8_t *)(data->ctx.tx_buf);
	} else {
		tx = 0;
	}

	while (!regs->INTFLAG.bit.DRE) {
	}

	regs->DATA.reg = tx;
	spi_context_update_tx(&data->ctx, 1, 1);

	while (!regs->INTFLAG.bit.RXC) {
	}

	rx = regs->DATA.reg;

	if (spi_context_rx_on(&data->ctx)) {
		*data->ctx.rx_buf = rx;
		spi_context_update_rx(&data->ctx, 1, 1);
	}
}

/* Fast path that transmits a buf */
static void spi_sam0_fast_tx(SercomSpi *regs, const struct spi_buf *tx_buf)
{
	const u8_t *p = tx_buf->buf;
	const u8_t *pend = tx_buf->buf + tx_buf->len;
	u8_t ch;

	while (p != pend) {
		ch = *p++;

		while (!regs->INTFLAG.bit.DRE) {
		}

		regs->DATA.reg = ch;
	}

	/* Note that the RX buf is full and the transmit may be ongoing */
}

/* Fast path that reads into a buf */
static void spi_sam0_fast_rx(SercomSpi *regs, struct spi_buf *rx_buf)
{
	u8_t *p = rx_buf->buf;
	size_t len = rx_buf->len;

	while (regs->INTFLAG.bit.RXC) {
		(void)regs->DATA.reg;
	}

	if (len <= 0) {
		return;
	}

	/*
	 * The code below interleaves the transmit of the next byte
	 * with the receive of the next.  The code is equivalent to:
	 *
	 * Transmit byte 0
	 * Loop:
	 * - Transmit byte n+1
	 * - Receive byte n
	 */

	/* Load the first outgoing byte */
	while (!regs->INTFLAG.bit.DRE) {
	}

	regs->DATA.reg = 0;

	while (len) {
		if (len != 0) {
			while (!regs->INTFLAG.bit.DRE) {
			}

			regs->DATA.reg = 0;
		}

		/*
		 * Decrement len while waiting for the transfer to
		 * complete.
		 */
		len--;

		while (!regs->INTFLAG.bit.RXC) {
		}

		*p++ = regs->DATA.reg;
	}

	/* Note that all transmits are complete and the RX buf is empty */
}

/* Fast path that writes and reads bufs of the same length */
static void spi_sam0_fast_txrx(SercomSpi *regs, const struct spi_buf *tx_buf,
			       struct spi_buf *rx_buf)
{
	const u8_t *psrc = tx_buf->buf;
	u8_t *p = rx_buf->buf;
	size_t len = rx_buf->len;

	while (regs->INTFLAG.bit.RXC) {
		(void)regs->DATA.reg;
	}

	if (len <= 0) {
		return;
	}

	/* See the comment in spi_sam0_fast_rx re: interleaving. */

	/* Load the first outgoing byte */
	while (!regs->INTFLAG.bit.DRE) {
	}

	regs->DATA.reg = *psrc++;

	while (len) {
		if (len != 0) {
			while (!regs->INTFLAG.bit.DRE) {
			}

			regs->DATA.reg = *psrc++;
		}

		len--;

		while (!regs->INTFLAG.bit.RXC) {
		}

		*p++ = regs->DATA.reg;
	}

	/* Note that all transmits are complete and the RX buf is empty */
}

/* Finish any ongoing writes and drop any remaining read data */
static void spi_sam0_finish(SercomSpi *regs)
{
	while (!regs->INTFLAG.bit.TXC) {
	}

	while (regs->INTFLAG.bit.RXC) {
		(void)regs->DATA.reg;
	}
}

/* Fast path where every overlapping tx and rx buffer is the same length */
static void spi_sam0_fast_transceive(const struct spi_config *config,
				     const struct spi_buf *tx_bufs,
				     size_t tx_count, struct spi_buf *rx_bufs,
				     size_t rx_count)
{
	const struct spi_sam0_config *cfg = config->dev->config->config_info;
	SercomSpi *regs = cfg->regs;

	while (tx_count != 0 && rx_count != 0) {
		spi_sam0_fast_txrx(regs, tx_bufs, rx_bufs);
		tx_bufs++;
		tx_count--;
		rx_bufs++;
		rx_count--;
	}

	for (; tx_count != 0; tx_count--) {
		spi_sam0_fast_tx(regs, tx_bufs++);
	}

	for (; rx_count != 0; rx_count--) {
		spi_sam0_fast_rx(regs, rx_bufs++);
	}

	spi_sam0_finish(regs);
}

/* Returns true if the request is suitable for the fast
 * path. Specifically, the bufs are a sequence of:
 *
 * - Zero or more RX and TX buf pairs where each is the same length.
 * - Zero or more trailing RX only bufs
 * - Zero or more trailing TX only bufs
 */
static bool spi_sam0_is_regular(const struct spi_buf *tx_bufs,
				size_t tx_count, struct spi_buf *rx_bufs,
				size_t rx_count)
{
	while (tx_count != 0 && rx_count != 0) {
		if (tx_bufs->len != rx_bufs->len) {
			return false;
		}

		tx_bufs++;
		tx_count--;
		rx_bufs++;
		rx_count--;
	}

	return true;
}

static int spi_sam0_transceive(const struct spi_config *config,
			       const struct spi_buf *tx_bufs, size_t tx_count,
			       struct spi_buf *rx_bufs, size_t rx_count)
{
	const struct spi_sam0_config *cfg = config->dev->config->config_info;
	struct spi_sam0_data *data = config->dev->driver_data;
	SercomSpi *regs = cfg->regs;
	int err;

	spi_context_lock(&data->ctx, false, NULL);

	err = spi_sam0_configure(config);
	if (err != 0) {
		goto done;
	}

	data->ctx.config = config;
	spi_context_cs_configure(&data->ctx);
	spi_context_cs_control(&data->ctx, true);

	/* This driver special case for the common send only, receive
	 * only, and transmit then receive operations.	This special
	 * casing is 4x faster than the spi_context() routines
	 * and also allows the transmit and receive to be interleaved.
	 */
	if (spi_sam0_is_regular(tx_bufs, tx_count, rx_bufs, rx_count)) {
		spi_sam0_fast_transceive(config, tx_bufs, tx_count, rx_bufs,
					 rx_count);
	} else {
		spi_context_buffers_setup(&data->ctx, tx_bufs, tx_count,
					  rx_bufs, rx_count, 1);

		do {
			spi_sam0_shift_master(regs, data);
		} while (spi_sam0_transfer_ongoing(data));
	}

	spi_context_cs_control(&data->ctx, false);

done:
	spi_context_release(&data->ctx, err);
	return err;
}

static int spi_sam0_release(const struct spi_config *config)
{
	struct spi_sam0_data *data = config->dev->driver_data;

	spi_context_unlock_unconditionally(&data->ctx);

	return 0;
}

static int spi_sam0_init(struct device *dev)
{
	const struct spi_sam0_config *cfg = dev->config->config_info;
	struct spi_sam0_data *data = dev->driver_data;
	SercomSpi *regs = cfg->regs;

	/* Enable the GCLK */
	GCLK->CLKCTRL.reg = cfg->gclk_clkctrl_id | GCLK_CLKCTRL_GEN_GCLK0 |
			    GCLK_CLKCTRL_CLKEN;

	/* Enable SERCOM clock in PM */
	PM->APBCMASK.reg |= cfg->pm_apbcmask;

	/* Connect pins to the peripheral */
	soc_gpio_configure(&cfg->pin_mosi);
	soc_gpio_configure(&cfg->pin_miso);
	soc_gpio_configure(&cfg->pin_sck);

	/* Disable all SPI interrupts */
	regs->INTENCLR.reg = SERCOM_SPI_INTENCLR_MASK;
	wait_synchronization(regs);

	spi_context_unlock_unconditionally(&data->ctx);

	/* The device will be configured and enabled when transceive
	 * is called.
	 */

	return 0;
}

static const struct spi_driver_api spi_sam0_driver_api = {
	.transceive = spi_sam0_transceive,
	.release = spi_sam0_release,
};

#define SPI_SAM0_DEFINE_CONFIG(n)                                            \
	static const struct spi_sam0_config spi_sam0_config_##n = {          \
		.regs = &SERCOM##n->SPI,                                     \
		.pm_apbcmask = PM_APBCMASK_SERCOM##n,                        \
		.gclk_clkctrl_id = GCLK_CLKCTRL_ID_SERCOM##n##_CORE,         \
		.ctrla = SERCOM_USART_CTRLA_RXPO(3) |                        \
			 SERCOM_USART_CTRLA_TXPO(1),                         \
		.pin_miso = PIN_SPI_SAM0_SERCOM##n##_MISO,                   \
		.pin_mosi = PIN_SPI_SAM0_SERCOM##n##_MOSI,                   \
		.pin_sck = PIN_SPI_SAM0_SERCOM##n##_SCK,                     \
	}

#define SPI_SAM0_DEVICE_INIT(n)                                              \
	SPI_SAM0_DEFINE_CONFIG(n);                                           \
	static struct spi_sam0_data spi_sam0_dev_data_##n = {                \
		SPI_CONTEXT_INIT_LOCK(spi_sam0_dev_data_##n, ctx),           \
		SPI_CONTEXT_INIT_SYNC(spi_sam0_dev_data_##n, ctx),           \
	};                                                                   \
	DEVICE_AND_API_INIT(spi_sam0_##n, CONFIG_SPI_##n##_NAME,             \
			    &spi_sam0_init, &spi_sam0_dev_data_##n,          \
			    &spi_sam0_config_##n, POST_KERNEL,               \
			    CONFIG_SPI_INIT_PRIORITY, &spi_sam0_driver_api)

#if CONFIG_SPI_0
SPI_SAM0_DEVICE_INIT(0);
#endif

#if CONFIG_SPI_1
SPI_SAM0_DEVICE_INIT(1);
#endif

#if CONFIG_SPI_2
SPI_SAM0_DEVICE_INIT(2);
#endif

#if CONFIG_SPI_3
SPI_SAM0_DEVICE_INIT(3);
#endif

#if CONFIG_SPI_4
SPI_SAM0_DEVICE_INIT(4);
#endif

#if CONFIG_SPI_5
SPI_SAM0_DEVICE_INIT(5);
#endif
