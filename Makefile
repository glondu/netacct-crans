all: netacct-crans

%: %.ml
	ocamlfind ocamlopt -w x -predicates opt -thread -package postgresql,pcap,bitstring,bitstring.syntax -syntax camlp4o -linkpkg -o $@ $<

clean:
	rm -f netacct-crans *.cm* *.o
