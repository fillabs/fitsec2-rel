all: install
clean:
	-make -C lib clean
	-make -C tests clean
	-make -C cshared clean
	-make -C fscrypt clean

tests: install FORCE
	make -C $@ all

install: cshared fscrypt FORCE
	make -C lib all

cshared: FORCE
	make -C $@ all

fscrypt: FORCE
	make -C $@ all

FORCE:
