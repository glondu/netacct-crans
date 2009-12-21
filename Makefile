all: netacct-crans

%: %.ml
	ocamlfind ocamlopt -w x -predicates opt -thread -package postgresql,calendar,pcap,bitstring,bitstring.syntax -syntax camlp4o -linkpkg -o $@ $<
