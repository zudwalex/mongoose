CWD = $(realpath $(CURDIR))
ZEPHYR_DIR ?= $(realpath ../../../zephyrproject)

example:
	true

build:
	cd $(ZEPHYR_DIR) && west build -b nucleo_h743zi -p auto $(CWD)/http-client

flash:
	cd $(ZEPHYR_DIR) && west flash

clean:
	rm -rf */*/mongoose.*
