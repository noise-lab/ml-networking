import datetime

categories = ['INACTIVE', 'WEB', 'AUDIO', 'VIDEO', 'GAMING']

inp = raw_input("Clear? Y/N\n")

if inp in ["y", "Y"]:
	with open('log.txt', 'w') as f:
		f.write("")

while True:
	for i, c in enumerate(categories):
		print("{}: {}".format(i, c))
	cat = raw_input()
	print("\n")
	time = datetime.datetime.now()
	with open('log.txt', 'a') as f:
		f.write(str(time) + '\n' + str(cat) + '\n')