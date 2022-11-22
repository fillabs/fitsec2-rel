all: install
clean:
	-make -C lib clean
	-make -C tests clean
	-make -C cshared clean

tests: install FORCE
	make -C $@ all

install: cshared FORCE
	make -C lib all

cshared: FORCE
	make -C $@ all

FORCE:
