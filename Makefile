#
# garuda Makefile

PREFIX=/usr/local

all:  build_garuda 

build_garuda:
	cd src/  ; make

install:
	scripts/install ${PREFIX}

uninstall:
	rm -rf ${PREFIX}/garuda	

clean:
	cd src/ ; make clean

