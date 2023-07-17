from src import parse_args

if __name__=='__main__':
  cmd_args = parse_args()
  print(list(cmd_args['ip']))