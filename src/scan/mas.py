# import masscan
# import json

# from objprint import op
# from pitricks.utils import make_parent_top

# make_parent_top(2)

# from ..conf import gconf

# mas = masscan.PortScanner()
# mas.scan(",".join(gconf['ip']), ports=",".join(map(str, gconf['port'])), arguments=f'--max-rate {gconf["threads"]}')
# op(json.loads(mas.scan_result)['scan'])