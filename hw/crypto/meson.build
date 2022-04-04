if nettle.found()
    softmmu_ss.add(when: 'CONFIG_ALLWINNER_CRYPTO_SUN4I_SS', if_true: files('allwinner-sun4i-ss.c'))
    softmmu_ss.add(when: 'CONFIG_ROCKCHIP_CRYPTO', if_true: files('rockchip-crypto.c'))
endif
