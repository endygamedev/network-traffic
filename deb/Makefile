SCAN=main
STATS=recipient
VER=sniffer_1.0-1_amd64

all:
	make -C ../src
	cp ../src/$(SCAN) ./$(VER)/usr/local/bin/ps-scanner
	cp ../src/$(STATS) ./$(VER)/usr/local/bin/ps-stats

install: build
	dpkg -i ./$(VER).deb

build:
	dpkg-deb --build --root-owner-group ./$(VER)

clean: remove
	rm -rf ./$(VER).deb

remove:
	dpkg -r packet-sniffer
