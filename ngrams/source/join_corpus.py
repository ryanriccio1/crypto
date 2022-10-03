import glob

read_files = glob.glob("**/*.txt", recursive=True)

with open("src.txt", "w", encoding="utf-8") as outfile:
    # write every txt down from this folder to a single file
    for idx, current_file in enumerate(read_files):
        print(f"{idx}/{len(read_files)}: {current_file}")
        with open(current_file, "r", encoding="utf-8") as infile:
            outfile.write(infile.read())
    text = outfile.read().split()
    print(f"Number of Words: {len(text)}")
    print("Done!")
