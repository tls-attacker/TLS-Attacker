#!/usr/bin/python

# standard modules
import math
import time
import sys


####################
def power_mod(b,e,n):
	accum = 1; i = 0; bpow2 = b
	while ((e>>i)>0):
		if((e>>i) & 1):
			accum = (accum*bpow2) % n
		bpow2 = (bpow2*bpow2) % n
		i+=1
	return accum

####################
def bitlen(i):
    len = 0
    while (i):
        i = (i >> 1)
        len += 1
    return len
####################
def intfloordiv(c,d):
	return int((c-(c%d))/d)

def intceildiv(c,d):
	if c%d==0:
		return intfloordiv(c,d)
	else:
		return intfloordiv(c,d)+1
####################

def extended_euclid(u, v):
# returns (c,r,s) such that c = r u + s v
	r = 1
	s = 0
	c = u
	v1 = 0
	v2 = 1
	v3 = v
	while v3 != 0:
		q = c / v3
		t1 = r - q * v1
		t2 = s - q * v2
		t3 = c - q * v3
		r = v1
		s = v2
		c = v3
		v1 = t1
		v2 = t2
		v3 = t3

	return int(c), int(r), int(s)

####################
def gcd(u,v):
	return extended_euclid(u, v)[0]

####################
def inverse_mod(a,p):
	if not gcd(a,p)==1:
		raise Exception("Inverse does not exist.")
		return False
	else:
		b = extended_euclid(a,p)[1]
		while b<0:
			b = b+p
		return b
####################

################################################################################
# define Manger Oracle
count = 0
countvalid=0

def MangerOracle(cc):
	global count,countvalid,d,N
	count += 1
	
	dec = power_mod(cc,d,N)

	if dec < B:
		countvalid += 1
		if count % 10000 == 0:
			print count,"oracle queries,",countvalid,"valid"
		return True
	else:
		if count % 10000 == 0:
			print count,"oracle queries,",countvalid,"valid"
		return False

################################################################################
# Perform attack
d=1
N=1
B=1

def perform_attack(Ns, es, ds, cs):
	global N
	N = int(Ns,16)
	global B
	B = 1<<(bitlen(N)-8)
	e = int(es,16)
	global d
	d = int(ds,16)
	c = int(cs,16)
	
	print "Parameters in Python accepted:"
	print "N: ", N
	print "e: ", e
	print "d: ", d
	print "c: ", c

	starttime = time.time()
	print "Modulus size:",int(math.ceil(math.log(N,2))),"bits."

	c0 = c

	# Step 0: Ensure that m in [0,B)
	fx = 1
	if not MangerOracle(c0):
		cx = c0
		fx += 1
		while True:
			cx = (power_mod(fx,e,N)*c0) % N
			if MangerOracle(cx):
				c0 = cx
				break
			else:
				fx += 1

	# Step 1
	f1 = int(2)
	while True:
		cc = (power_mod(f1,e,N)*c0) % N
		if MangerOracle(cc):
			f1 *= 2
		else:
			break

	# Step 2
	f2 = int(intfloordiv(N+B,B)*f1/2)
	while True:
		cc = (power_mod(f2,e,N)*c0) % N
		if not MangerOracle(cc):
			f2 = f2 + f1/2
		else:
			break

	# Step 3
	mmin = intceildiv(N,f2)
	mmax = intfloordiv(N+B,f2)

	previntervalsize=0
	while True:
		ftmp = intfloordiv(2*B,mmax-mmin)
		i = intfloordiv(ftmp*mmin,N)
		f3 = intceildiv(i*N,mmin)
		cc = (power_mod(f3,e,N)*c0) % N
		if not MangerOracle(cc):
			mmin = intceildiv(i*N+B,f3)
		else:
			mmax = intfloordiv(i*N+B,f3)

		if mmax == mmin:
			break

		intervalsize = int(math.ceil(math.log(mmax-mmin)))
		if not intervalsize == previntervalsize:
			if intervalsize % 10 == 0:
				print ">> Manger running. Interval size:",intervalsize,"bit."
				previntervalsize=intervalsize


	resultm = 1
	if fx == 1:
		resultm = mmin
	else:
		inverse = inverse_mod(fx, N)
		resultm = (inverse * mmin) % N
	
	print "result: ", resultm

	stoptime = time.time()
	print "Time elapsed:",stoptime-starttime,"seconds (=",(stoptime-starttime)/60,"minutes)"
	print "Modulus size:",int(math.ceil(math.log(N,2))),"bit. About",(stoptime-starttime)/math.ceil(math.log(N,2)),"seconds per bit."
	print count,"oracle queries performed,",countvalid,"valid ciphertexts."
	print "verification:",power_mod(resultm,e,N)

	return resultm

