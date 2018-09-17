import paging as Paging
import memory as Memory
import sys, argparse

def hexadecimal(value):
    return int(value, 16)

def gva2gpa_npt(paginator, gva, gcr3, nptp):
    print ":: Guest Virtual Address: " + str(hex(gva))
    return paginator.guest_vtop_npt(gva, gcr3, nptp)

def gpa2hpa_npt(paginator, gpa, nptp):
    print ":: Guest Physical Address: " + str(hex(gpa))
    return paginator.vtop(gpa, nptp)

def main(args):
    paginator = Paging.Paginator(Memory.RawMemoryAbstractor(args.file))
    gpa = args.gpa
    if args.gva:
        if args.gcr3 == None:
            raise ValueError("--gva requires --gcr3")
        gpa = gva2gpa_npt(paginator, args.gva, args.gcr3, args.nptp)
    print ":: System Physical Address: " + str(hex(gpa2hpa_npt(paginator, gpa, args.nptp)))

parser = argparse.ArgumentParser(description="Translate guest virtual/physical address to host physical address through Nested Paging Table", prog="translator")
parser.add_argument("--file", "-f", type=str, action="store", required=True, help="Memory dump file")
parser.add_argument("--gcr3", type=hexadecimal, action="store", help="Guest CR3 for guest address translation")
parser.add_argument("--nptp", type=hexadecimal, action="store", help="Nested Page Table Pointer from VMCB", required=True)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--gva", type=hexadecimal, action="store", help="Guest Virtual Address")
group.add_argument("--gpa", type=hexadecimal, action="store", help="Guest Physical Address")

main(parser.parse_args())
