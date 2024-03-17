import sys

def main(nm_output_path, instrumentation_output_path):
    # Read the contents of the nm output file
    with open(nm_output_path, 'r') as nm_file:
        nm_output = nm_file.read()

    # Read the contents of the instrumentation output file
    with open(instrumentation_output_path, 'r') as instrumentation_file:
        instrumentation_output = instrumentation_file.read()

    # Remove nm_output lines that don't start with a hex address
    nm_output_lines = nm_output.split("\n")
    nm_output_lines = [line for line in nm_output_lines if len(line) > 0 and line[0].isdigit()]

    # Create a dictionary of addresses to symbols
    addr2sym = {}
    for line in nm_output_lines:
        parts = line.split(" ")
        addr = int(parts[0], 16)
        sym = parts[-1]
        addr2sym[addr] = sym

    # Remove all lines from the instrumentation output that don't start with "FUNC:"
    instrumentation_output_lines = instrumentation_output.split("\n")
    instrumentation_output_lines = [line for line in instrumentation_output_lines if len(line) > 0 and line.startswith("FUNC:")]

    # create a dictionary of symbols and their commulative cycle count
    sym2cycle = {}

    # Replace the addresses with symbols
    for i in range(len(instrumentation_output_lines)):
        line = instrumentation_output_lines[i]
        parts = line.split(",")
        parts = [part.strip() for part in parts]
        func = parts[0].split(":")
        cycle = int(parts[1].split(":")[1])
        addr = int(func[1], 16)
        sym = addr2sym[addr]
        parts[0] = f"{func[0]}:{sym}"
        if sym in sym2cycle:
            sym2cycle[sym] += cycle
        else:
            sym2cycle[sym] = cycle
        instrumentation_output_lines[i] = "{:<30}\t{:<20}".format(*parts)


    # print how long each function took in descending order
    print("Function\t\t\tTOTAL Cycle Count")
    sym2cycle = dict(sorted(sym2cycle.items(), key=lambda item: item[1], reverse=True))
    for key in sym2cycle:
        print("{:<30}\t{:<20}".format(key, sym2cycle[key]))



    # print the output
    print("\n\n")
    print("\n".join(instrumentation_output_lines))



# Example usage
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python addr2sym.py <nm_output_path> <instrumentation_output_path>")
        sys.exit(1)

    nm_output_path = sys.argv[1]
    instrumentation_output_path = sys.argv[2]
    main(nm_output_path, instrumentation_output_path)