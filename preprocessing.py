###############################################################
###   Cloudbook IDS (Intrusion Detection System) use case   ###
###############################################################

# This program allows the preprocessing of large .csv files to use them in an Intrusion Detection System
# This program is the updated implementation of the preprocessing module of Javier Alberca's TFM
# 	(available at:  https://github.com/jalberca/tfm-ids_and_machine_learning  ).



#####   IMPORTS   #####

# System
import os, platform

# Basic
import time
import random
import json

# Processing
import pandas as pd
from sklearn import preprocessing
from scipy import stats



#####   GLOBAL VARIABLES   #####

#__CLOUDBOOK:GLOBAL__
# List in which the columns processed are appended
done = []

# The input and output directories (for cloudbook they are inside .../distributed/working_dir/)
input_path = "./input" 		# os.environ['HOME'] + os.sep + "ids-files" + os.sep + "input"
output_path = "./output" 	# os.environ['HOME'] + os.sep + "ids-files" + os.sep + "output"

# The file which will be used as data input
dataset_file = "100dataset.csv"



#####   FUNCTIONS   #####

#__CLOUDBOOK:DU0__
def du0_print(*args, **kwargs):
	print(*args, **kwargs)


#__CLOUDBOOK:DU0__
def du0_ask_for_input_file():
	global input_path
	global output_path
	global dataset_file

	if not os.path.exists(input_path):
		print("The input path ("+input_path+") does not exist. Creating it...")
		os.mkdir(input_path)
	if not os.path.exists(output_path):
		print("The output path ("+output_path+") does not exist. Creating it...")
		os.mkdir(output_path)

	print("Write the input file you want to process (from .../input/).")
	print("The file '100dataset.csv' will be used by default.")
	input_file = None
	while not input_file:
		input_file = input("File (include extension): ")
		if input_file=="":
			input_file = dataset_file
		if not os.path.exists(input_path+os.sep+input_file):
			print("The file "+input_path+os.sep+input_file+" does not exist. Try again.\n")
			input_file = None
	
	print("Input file successfully set.")
	dataset_file = input_file
	return


# This function assigns a single column to be processed.
def assign_piece():
	global done

	aux1 = ["Timestamp", "Duration", "Src_IP", "Dst_IP", "Src_Port", "Dest_Port", "Proto", "Flags",\
			"Forward_Status", "Service_type", "Number_of_Packets", "Bytes", "Result"]
	chosen = random.choice(aux1)
	while chosen in done:
		chosen = random.choice(aux1)
	col = aux1.index(chosen)
	du0_print("The chosen is:", chosen)
	done.append(chosen)
	du0_print("Already done:", done)

	return col


#__CLOUDBOOK:PARALLEL__
def process_piece(col):
	global input_path
	global output_path
	global dataset_file

	du0_print("Splitting column", str(col))
	time_start_process_piece = time.time()

	data = pd.read_csv(input_path+os.sep+dataset_file, sep=',', usecols=[col], squeeze=True, encoding='utf-8', header=None)
	du0_print(list(data[0:5]))

	if int(col)==1 or int(col)==10 or int(col)==11:
		data = stats.zscore(data)
		data = pd.DataFrame(data)
		du0_print("Processed Data:", list(data[0:5]))
		data.dropna(inplace=True)
		data.to_csv(output_path + os.sep + str(col), header=False, index=False)
		du0_print("Processing time", time.time()-time_start_process_piece)

	elif int(col)==0 or int(col)==8:
		du0_print("Column not to be processed")

	elif int(col)==12:
		data = data.replace(["dos", "scan11", "scan44", "nerisbotnet", "blacklist", "anomaly-udpscan",\
							 "anomaly-sshscan", "anomaly-spam", "background"], [0, 1, 1, 2, 3, 4, 4, 5, 6])
		du0_print("Processed Data:", list(data[0:5]))
		data.dropna(inplace=True)
		data.to_csv(output_path + os.sep + str(col), header=False, index=False)
		du0_print("Processing time", time.time()-time_start_process_piece)

	else:
		le = preprocessing.LabelEncoder()
		data = le.fit_transform(data)
		data = pd.DataFrame(data)
		du0_print("Processed Data:", list(data[0:5]))
		data.dropna(inplace=True)
		data.to_csv(output_path + os.sep + str(col), header=False, index=False)
		du0_print("Processing time", time.time()-time_start_process_piece)


def create_final_dataset():
	global output_path
	dataset = pd.DataFrame()

	# Use only number files (columns) and exclude any other file
	files = os.listdir(output_path)
	int_files = []
	for file in files:
		try:
			int_file = int(file)
			int_files.append(int_file)
		except:
			du0_print("Ommitting file", file)

	int_files.sort()
	du0_print(int_files)

	for int_file in int_files:
		piece = pd.read_csv(output_path + os.sep + str(int_file), sep=",", squeeze=True)
		dataset = pd.concat([dataset,piece], axis=1)
		du0_print(list(dataset))

	piece = None
	dataset.to_csv(output_path + os.sep + "FINALDATASET.csv", header=False, index=False)



#####   MAIN FUNCTION   #####

#__CLOUDBOOK:MAIN__
def main():
	global done

	try:
		__CLOUDBOOK__ # If this does not exist, we are not in cloudbook
		in_cloudbook = True
	except Exception:
		in_cloudbook = False

	if in_cloudbook:
		du0_print("\n\n ####################   CLOUDBOOK-BASED DATASET PREPROCESSING PROGRAM   #################### \n")
	else:
		du0_print("\n\n ####################   DATASET PREPROCESSING PROGRAM (ONE MACHINE)   #################### \n")
	du0_ask_for_input_file()

	du0_print("\n\n ########## START TIMER ########## \n")
	total_time_start = time.time()

	# Assign tasks
	du0_print("\n\n ##########   START PIECES ASSIGNMENT   ########## \n")
	cols = []
	for i in range(13):
		col = assign_piece()
		cols.append(col)
	du0_print("All pieces have been assigned")

	# Process the columns in parallel
	du0_print("\n\n ##########   START PREPROCESSING   ########## \n")
	for col in cols:
		process_piece(col)

	#__CLOUDBOOK:SYNC__
	du0_print("All pieces have been processed")

	du0_print("\n\n ##########   CREATING OUTPUT FILE   ########## \n")
	create_final_dataset()
	du0_print("Total time", time.time()-total_time_start)
	if in_cloudbook:
		du0_print("\n\n ####################   CLOUDBOOK DONE   #################### \n")
	else:
		du0_print("\n\n ####################   DONE   #################### \n")


#__CLOUDBOOK:BEGINREMOVE__
if __name__ == '__main__':
	main()
#__CLOUDBOOK:ENDREMOVE__
