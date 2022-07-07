SCANNER1=ps-scanner-1
SCANNER2=ps-scanner-2
STATS=ps-stats
PACK=sniffer_1.0-1_amd64

all:
	make -C ../src/
	cp ../src/$(SCANNER1) ./$(PACK)/usr/local/bin/$(SCANNER1)
	cp ../src/$(SCANNER2) ./$(PACK)/usr/local/bin/$(SCANNER2)
	cp ../src/$(STATS) ./$(PACK)/usr/local/bin/$(STATS)

install: build
	dpkg -i ./$(PACK).deb

build:
	dpkg-deb --build --root-owner-group ./$(PACK)

clean: remove
	rm -rf ./$(PACK).deb
	rm -rf ./$(PACK)/usr/local/bin/*

remove:
	dpkg -r packet-sniffer
