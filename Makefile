export BOARD=mw300_rd
%:
	$(MAKE) APP=$(PWD)/ BIN_DIR=$(PWD)/bin -C ../wmsdk_bundle-3.5.32 $@