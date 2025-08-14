## File formats
### `netspec`
```
5           # Number of nodes
1 1000      # Each line specifies a node's MAC address and IP address
2 2000
3 3000
4 4000
5 5000
10          # Number of edges
1 2 1       # Each line specifies the MAC addresses of the endpoints
            # of that edge
            # along with cost of the link
            # so this line represents an edge between
            # (mac:1) and (mac:2) with link cost 1
            # this link cost is served to you as
            # the distance argument in receive_packet
1 3 1
1 4 1
1 5 1
2 3 1
2 4 1
2 5 1
3 4 1
3 5 1
4 5 1
```
### `msgs`
```
MSG REPE 100 1 5000 testing     # MSG lines indicate segments that will be sent
                                # this line says that a segment with contents "testing" is to be sent
                                # 100 times from (mac:1) with destination (ip:5000)
DOWN 4
MSG 1 5000 testing              # if REPE is omitted the segment is sent once
MSG REPE 100 3 6000 testing     # can have multiple MSG lines together
DOWN 3                          # UP/DOWN represents nodes being made up/down
DOWN 2                          # your algorithm is allowed to converge after ups/downs are done
MSG REPE 100 1 5000 testing
UP 3
MSG REPE 100 1 5000 testing
UP 4
MSG REPE 100 1 5000 testing
```
