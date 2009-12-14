all: netacct-crans

%: %.ml
	ocamlfind ocamlopt -package pcap,bitstring,bitstring.syntax -syntax camlp4o -linkpkg -o $@ $<
