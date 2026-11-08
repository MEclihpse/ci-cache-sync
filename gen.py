import sys, itertools
shard=int(sys.argv[1]); total=int(sys.argv[2])
brand=["turbo","truboloop","turboloop","turbohub","hub","loop","devdady","devdaddy","dady","daddy","promethex","aifos","dpin","predict","saker","jacky","chris","tech","admin","root","neon","vercel","bondinglabs","solana","bsc","bnb","wallet","turboloopofficial"]
def cases(w):
    out={w,w.capitalize(),w.upper()}
    if len(w)>4: out.add(w[:1].upper()+w[1:4].capitalize()+w[4:])
    if len(w)>6: out.add(w[:1].upper()+w[1:3]+w[3:4].upper()+w[4:])
    return out
t1=set()
for b in brand: t1 |= cases(b)
t1=sorted(t1)
t2=["","hub","loop","dev","dady","daddy","admin","root","turbo","truboloop","turboloop","123456","12345","1234","123","1","2026","2025","2024","!","@","#"]
seps=["","@","#","!","_","-",".","@2026","#2026","!2026"]
tails=["","!","@","#","$","!!","123","1234","12345","123456","2024","2025","2026","!2026","@2026","#2026","2026!","123456!","@123456","#123456"]
def gen():
    for a in t1:
        for s in seps:
            for b in t2:
                for t in tails:
                    yield a+s+b+t
        for t in tails:
            yield a+t
            yield a+t.capitalize()
i=0; w=sys.stdout
for c in gen():
    if i%total==shard: w.write(c+"\n")
    i+=1
