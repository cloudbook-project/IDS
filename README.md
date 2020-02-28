# IDS (Intrusion Detection System) use case

This program uses cloudbook to allow the preprocessing of large .csv files to use them in an Intrusion Detection System. It is the updated implementation of the preprocessing module of Javier Alberca's TFM (available at: https://github.com/jalberca/tfm-ids_and_machine_learning ).


## How does it work

To launch the program in standalone mode

1. Run `python3 preprocessing` in a console.

To launch the program in Cloudbook you will need to:

1. Create the project folder (eg. "preprocess_ids"), and copy the source code of the program to original.
2. Use the maker to split it in deployeble units with `python3 cloudbook_maker -project_folder preprocess_ids`
3. Then run the GUI with `python3 gui.py` and create and launch agents.
4. Use the deployer to assign the deployable units `pytohn3 cloudbook_deployer.py -project_folder preprocess_ids`
5. Run Cloudbook: `python3 cloudbook_run.py -project_folder preprocess_ids`

When the program is running it will ask for the file you want to preprocess (by default it takes "100dataset.csv"). Inserting it by the console and pressing enter will trigger all the preprocessing and output file will be written ("FINALDATASET.csv").


### Cloudbook links

Agent: https://github.com/cloudbook-project/cloudbook_agent

Deployer: https://github.com/cloudbook-project/cloudbook_deployer

Maker: https://github.com/cloudbook-project/cloudbook_maker2
