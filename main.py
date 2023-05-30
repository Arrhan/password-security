import requests #this module allows us to make a request as if we have a browser and get data back from it 
import hashlib
import sys

#Store passwords as hash functions along with K anonymity, which allows for companies to recieve info about us but not know who we are
#hash functions are one way and idempotent

def request_api_data(first_five_hash): #Request api for data based on first 5 characters of hash for anonymity
    url='https://api.pwnedpasswords.com/range/'+ str(first_five_hash) 
    response=requests.get(url)
    if response.status_code!=200:
        raise RuntimeError(f"Response status was {response.status_code}, check the API information again")
    return response

def hash_converter(password): #Check if full password exists in api data
    hash_password=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return hash_password

def get_leaks(response, hash_password_tail): #Find how many leaks password was in
    hashes=(line.split(':') for line in response.text.splitlines())
    for h,count in hashes:
        if hash_password_tail==h:
            return count
        else:
            continue
    return 0

def api_checker(password):
    hash_password=hash_converter(password)
    anonymity_hash, tail= hash_password[0:5], hash_password[5:]
    response=request_api_data(anonymity_hash)
    return get_leaks(response, tail)

#Building function to be able to check multiple passwords at once
def main(args):
    for password in args:
        count=api_checker(password)
        if count:
            print(f"{password} was found {count} times")
        else:
            print(f"{password} was found 0 times")

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))