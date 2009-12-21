all: netacct-crans

%: %.ml
	ocamlfind ocamlopt -predicates opt -package pcap,bitstring,bitstring.syntax -syntax camlp4o -linkpkg -o $@ $<
