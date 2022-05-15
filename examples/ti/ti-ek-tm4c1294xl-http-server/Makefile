NAME ?= $(notdir $(CURDIR))

build:
	git clone --depth 1 https://github.com/mongoose-examples/$(NAME)
	cp ./../../../mongoose.[ch] $(NAME)/
	/opt/ti/ccs/eclipse/eclipse -noSplash -data $(CURDIR) -application com.ti.ccstudio.apps.projectBuild -ccs.autoImport -ccs.projects http_server -ccs.configuration Release

clean:
	rm -rf $(NAME)