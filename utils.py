def filter_data(data, col, pred):
	return eval("data[data[\"{}\"]{}]".format(col, pred if pred.startswith(".") else " " + pred))