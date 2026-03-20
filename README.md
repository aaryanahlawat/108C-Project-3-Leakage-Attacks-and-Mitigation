#Procedure

We aim to use the Path ORAM research paper psuedocode to guide us on the server implementation of PathORAM and use .txt files to recreate an input and output. We will design purely the PathORAM implementaiton without client-server scripts for simplicity sake. the input.txt file should read a client's query into the PathORAM server, where output.txt should hold the data that is seen on the server's end.

Assumptions:

Output of server txt file should be a binary tree, represented with a flat array

#Notes Before trying out script:
Must install ChicagoCrimes.csv from https://data.cityofchicago.org/Public-Safety/Crimes-2001-to-Present/ijzp-q8t2/data_preview
Rename CSV to ChicagoCrimes.csv or just change script input files below. Also have an output.txt file ready.

# Step 1 — regenerate input (you may have already done this correctly)
python3 prep_input.py \
    --dataset ChicagoCrimes.csv \
    --attribute "Primary Type" \
    --rows 1000 --se-mode \
    --output input.csv --value-map value_map.json

# Step 2 — kill and restart server, then rerun client with the fixed client.py
python3 server.py   # new terminal

python3 client.py input.csv output.txt \
    -a 2 -l 10 -x 2 --query-log queries.jsonl

# Step 3 — now attack will work
python3 attack.py \
    --dataset ChicagoCrimes.csv \
    --attribute "Primary Type" \
    --query-log queries.jsonl \
    --value-map value_map.json \
    --trials 100 --seed 42
