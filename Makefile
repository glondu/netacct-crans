all: netacct-crans pcap-capture-one

%: %.ml
	ocamlfind ocamlopt -w x -dtypes -predicates opt -thread -package str,syslog,postgresql,pcap,bitstring,bitstring.syntax -syntax camlp4o -linkpkg -o $@ $<

clean:
	rm -f *.cm* *.o *.native *.annot netacct-crans pcap-capture-one
