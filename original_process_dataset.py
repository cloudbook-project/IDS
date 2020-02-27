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


# This function assigns a single column to be processed.
def assign_piece():
	global done

	aux1 = ["Timestamp", "Duration", "Src_IP", "Dst_IP", "Src_Port", "Dest_Port", "Proto", "Flags",\
			"Forward_Status", "Service_type", "Number_of_Packets", "Bytes", "Result"]
	chosen = random.choice(aux1)
	while chosen in done:
		chosen = random.choice(aux1)
	col = aux1.index(chosen)
	print("The chosen is:", chosen)
	done.append(chosen)
	print("Already done:", done)

	return col


#__CLOUDBOOK:PARALLEL__
def process_piece(col):
	global input_path
	global output_path
	global dataset_file
	print("########################### SPLITTING COLUMN "+str(col)+" #################################")
	time_start_process_piece = time.time()

	data = pd.read_csv(input_path+os.sep+dataset_file, sep=',', usecols=[col], squeeze=True, encoding='utf-8', header=None)
	print(data[0:5])

	if int(col)==1 or int(col)==10 or int(col)==11:
		data = stats.zscore(data)
		data = pd.DataFrame(data)
		print("Processed Data:", data[0:5])
		data.dropna(inplace=True)
		data.to_csv(output_path + os.sep + str(col), header=False, index=False)
		print("Processing time", time.time()-time_start_process_piece)

	elif int(col)==0 or int(col)==8:
		print("Column not to be processed")

	elif int(col)==12:
		data = data.replace(["dos", "scan11", "scan44", "nerisbotnet", "blacklist", "anomaly-udpscan",\
							 "anomaly-sshscan", "anomaly-spam", "background"], [0, 1, 1, 2, 3, 4, 4, 5, 6])
		print("Processed Data:", data[0:5])
		data.dropna(inplace=True)
		data.to_csv(output_path + os.sep + str(col), header=False, index=False)
		print("Processing time", time.time()-time_start_process_piece)

	else:
		le = preprocessing.LabelEncoder()
		data = le.fit_transform(data)
		data = pd.DataFrame(data)
		print("Processed Data:", data[0:5])
		data.dropna(inplace=True)
		data.to_csv(output_path + os.sep + str(col), header=False, index=False)
		print("Processing time", time.time()-time_start_process_piece)


def create_final_dataset():
	global output_path
	dataset = pd.DataFrame()
	files = os.listdir(output_path)
	files = list(map(int,files))
	files.sort()
	print(files)

	for fname in files:
		piece = pd.read_csv(output_path + os.sep + str(fname), sep=",", squeeze=True)
		dataset = pd.concat([dataset,piece], axis=1)
		print(dataset)

	piece = None
	dataset.to_csv(output_path + os.sep + "FINALDATASET.csv", header=False, index=False)




#####   MAIN FUNCTION   #####

#__CLOUDBOOK:MAIN__
def main():
	global done
	total_time_start = time.time()
	print("################# STARTING CLOUDBOOK-BASED DATASET PREPROCESSING #################")

	# Assign tasks
	cols = []
	for i in range(13):
		col = assign_piece()
		cols.append(col)

	# Process the columns in parallel
	for col in cols:
		process_piece(col)

	#__CLOUDBOOK:SYNC__
	create_final_dataset()
	print("Total time", time.time()-total_time_start)
	print("################# CLOUDBOOK DONE #################")


#__CLOUDBOOK:BEGINREMOVE__
if __name__ == '__main__':
	main()
#__CLOUDBOOK:ENDREMOVE__