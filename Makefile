all: netacct-crans.native pcap-capture-one.native

%.native: %.ml
	ocamlfind ocamlopt -w x -dtypes -predicates opt -thread -package str,syslog,postgresql,pcap,bitstring,bitstring.syntax -syntax camlp4o -linkpkg -o $@ $<

clean:
	rm -f *.cm* *.o *.native *.annot
