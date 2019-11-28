import base64
import hashlib
import requests
import re
import binascii
import collections
import string
import urllib.parse
import discord
from factordb.factordb import FactorDB
from discord.ext import commands

#TODO: l14ck3r0x01: ROT47 , base32 encoding

class EncodingDecoding(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def b64(self, ctx, encode_or_decode, string):
        byted_str = str.encode(string)
        
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            decoded = base64.b64decode(byted_str).decode('utf-8')
            await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            encoded = base64.b64encode(byted_str).decode('utf-8').replace('\n', '')
            await ctx.send(encoded)

    @commands.command()
    async def b32(self, ctx, encode_or_decode, string):
        byted_str = str.encode(string)
        
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            decoded = base64.b32decode(byted_str).decode('utf-8')
            await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            encoded = base64.b32encode(byted_str).decode('utf-8').replace('\n', '')
            await ctx.send(encoded)
            
    @commands.command()
    async def b16(self, ctx, encode_or_decode, string):
        byted_str = str.encode(string)
        
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            decoded = base64.b16decode(byted_str).decode('utf-8')
            await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            encoded = base64.b16encode(byted_str).decode('utf-8').replace('\n', '')
            await ctx.send(encoded)                

    @commands.command()
    async def factordb(self, ctx,string):
        byted_str = int(string)
        f = FactorDB(byted_str)
        f.get_factor_list()
        f.connect()
        out = f.get_factor_list()
        await ctx.send(out)
    

    @commands.command()
    async def hashfind(self, ctx, string):
        byted_str = str(string)
        url = "https://md5decrypt.net/en/HashFinder/"

        headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "SOMETHING",
        "Cookie": "SOMETHING",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
        }

        data = "hash="+ byted_str + "&crypt=Search"
        conn = requests.post(url, headers=headers, data=data)
        sd = str(conn.content)
        #print (conn.content)
        sd1 = re.compile('Possible kind of hash :<br /><br />(.*)</fieldset><br />')
        sd2 = sd1.findall(sd)
        #print (sd2)
        await ctx.send(sd2)



    @commands.command()
    async def md4(self, ctx, encode_or_decode, string):
        byted_str = str(string)
        
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            url = "https://md5decrypt.net/en/Md4/"

            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "SOMETHING",
            "Cookie": "SOMETHING",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded"
            }

            data = "hash="+byted_str+"&captcha6866=&ahah6866=8186af7ab64961dd5f1aac0f47a78d41&decrypt=Decrypt"

            conn = requests.post(url, headers=headers, data=data)

            sd = str(conn.content)

            #print (conn.content)

            sd1 = re.compile(': <b>(.*)</b><br/><br/>Found')
            sd2 = sd1.findall(sd)
            #print (sd2)
            await ctx.send(sd2)
    
            #await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            url = "https://md5decrypt.net/en/Md4/"

            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "SOMETHING",
            "Cookie": "SOMETHING",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded"
            }
            data = "hash="+byted_str+"&captcha55987=&ahah55987=9613b27057c39fe2cb8ec4132b4b900f&crypt=Encrypt"
            conn = requests.post(url, headers=headers, data=data)
            sd = str(conn.content)
            #print (conn.content)
            sd1 = re.compile('= <b>(.*)</b><br/><br/>')
            sd2 = sd1.findall(sd)
            #print (sd2)
            await ctx.send(sd2)

    @commands.command()
    async def onlinehash(self, ctx, hah, string):
        hah = hah
        hashtype = string
        url = "https://md5decrypt.net/en/Api/api.php?hash="+hah+"&hash_type="+hashtype+"&email=cocjackcoc1@gmail.com&code=3e88dfd2157965bf"
        headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "SOMETHING",
        "Cookie": "SOMETHING",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
        }
        
        conn = requests.get(url, headers=headers)
        sd = (conn.content)
        await ctx.send(sd)
'''
    @commands.command()
    async def md5online(self, ctx, string):
        byted_str = str(string)
        
        
        url = "https://md5decrypt.net/en/"
        headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "SOMETHING",
        "Cookie": "SOMETHING",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "hash="+byted_str+"&captcha55987=&ahah55987=e7488f7e351b792c294f661e62fefb3f&decrypt=Decrypt"
        conn = requests.post(url, headers=headers, data=data)
        sd = str(conn.content)
        #print (conn.content)
        sd1 = re.compile(': <b>(.*)</b><br/><br/>Found')
        sd2 = sd1.findall(sd)
        #print (sd2)
        await ctx.send(sd2)

    @commands.command()
    async def sha1online(self, ctx, string):
        byted_str = str(string)
        
        
        url = "https://md5decrypt.net/en/Sha1/"
        headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "SOMETHING",
        "Cookie": "SOMETHING",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "hash="+byted_str+"&captcha55987=&ahah55987=fb134ea9b5ee814f2c343f68d56ce1a7&decrypt=Decrypt"
        conn = requests.post(url, headers=headers, data=data)
        sd = str(conn.content)
        #print (conn.content)
        sd1 = re.compile(': <b>(.*)</b><br/><br/>Found')
        sd2 = sd1.findall(sd)
        #print (sd2)
        await ctx.send(sd2)

    @commands.command()
    async def sha256online(self, ctx, string):
        byted_str = str(string)
        
        
        url = "https://md5decrypt.net/en/Sha256/"
        headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "SOMETHING",
        "Cookie": "SOMETHING",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "hash="+byted_str+"&captcha987987=&ahah987987=0eee9cc3a434737747bc9755029204c5&decrypt=Decrypt"
        conn = requests.post(url, headers=headers, data=data)
        sd = str(conn.content)
        #print (conn.content)
        sd1 = re.compile(': <b>(.*)</b><br/><br/>Found')
        sd2 = sd1.findall(sd)
        #print (sd2)
        await ctx.send(sd2)

    @commands.command()
    async def sha512online(self, ctx, string):
        byted_str = str(string)
        
        
        url = "https://md5decrypt.net/en/Sha512/"
        headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "SOMETHING",
        "Cookie": "SOMETHING",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "hash="+byted_str+"&captcha687=&ahah687=1ef1a596b66c820a9105029a3f98524c&decrypt=Decrypt"
        conn = requests.post(url, headers=headers, data=data)
        sd = str(conn.content)
        #print (conn.content)
        sd1 = re.compile(': <b>(.*)</b><br/><br/>Found')
        sd2 = sd1.findall(sd)
        #print (sd2)
        await ctx.send(sd2)     

'''     

    @commands.command()
    async def md5(self, ctx, encode_or_decode, string):
        byted_str = str(string)
        
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            f = open('/home/ubuntu/NullCTF/cogs/rockyou.txt', 'r' , encoding='latin-1')
            for z in f:
                line = str(z).strip('\n')
                #print (line) 
                decoded = hashlib.md5(line.encode('utf-8')).hexdigest().replace('\n', '')
                if byted_str == decoded:        
                    sd = "MD5 Decode :",line
                    await ctx.send(sd)
    
            #await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            encoded = hashlib.md5(byted_str.encode('utf-8')).hexdigest().replace('\n', '')
            encoded = "MD5 Encode:", encoded
            await ctx.send(encoded)

    @commands.command()
    async def sha1(self, ctx, encode_or_decode, string):
        byted_str = str(string)
        
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            f = open('/home/ubuntu/NullCTF/cogs/rockyou.txt', 'r' , encoding='latin-1')
            for z in f:
                line = str(z).strip('\n')
                #print (line) 
                decoded = hashlib.sha1(line.encode('utf-8')).hexdigest().replace('\n', '')
                if byted_str == decoded:        
                    sd = "SHA1 Decode :",line
                    await ctx.send(sd)
    
            #await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            encoded = hashlib.sha1(byted_str.encode('utf-8')).hexdigest().replace('\n', '')
            encoded = "SHA1 Encode:", encoded
            await ctx.send(encoded)
            
    @commands.command()
    async def sha256(self, ctx, encode_or_decode, string):
        byted_str = str(string)
        
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            f = open('/home/ubuntu/NullCTF/cogs/rockyou.txt', 'r' , encoding='latin-1')
            for z in f:
                line = str(z).strip('\n')
                #print (line) 
                decoded = hashlib.sha256(line.encode('utf-8')).hexdigest().replace('\n', '')
                if byted_str == decoded:        
                    sd = "SHA256 Decode :",line
                    await ctx.send(sd)
    
            #await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            encoded = hashlib.sha256(byted_str.encode('utf-8')).hexdigest().replace('\n', '')
            encoded = "SHA256 Encode:", encoded
            await ctx.send(encoded)
            
    @commands.command()
    async def sha512(self, ctx, encode_or_decode, string):
        byted_str = str(string)
        
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            f = open('/home/ubuntu/NullCTF/cogs/rockyou.txt', 'r' , encoding='latin-1')
            for z in f:
                line = str(z).strip('\n')
                #print (line) 
                decoded = hashlib.sha512(line.encode('utf-8')).hexdigest().replace('\n', '')
                if byted_str == decoded:        
                    sd = "SHA512 Decode :",line
                    await ctx.send(sd)
    
            #await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            encoded = hashlib.sha512(byted_str.encode('utf-8')).hexdigest().replace('\n', '')
            encoded = "SHA512 Encode:", encoded
            await ctx.send(encoded)
                                    
    
    @commands.command()
    async def rsa(self, ctx, p,q,n,e,c):
        def egcd(a, b):
            if a == 0:
                return (b, 0, 1)
            else:
                g, y, x = egcd(b % a, a)
                return (g, x - (b // a) * y, y)
        def modinv(a, m):
            g, x, y = egcd(a, m)
            if g != 1:
                raise Exception('modular inverse does not exist')
            else:
                return x % m





        p = int(p)

        q = int(q)

        n = int(n)
        e = int(e)
        c = int(c)

        fi = (p-1)*(q-1)
        d = modinv(e, fi)
        sd1 = ("%x" % pow(c, d, n))

        aw = bytes.fromhex(sd1).decode('utf-8')
        await ctx.send(aw)
        #print (aw)
    
    @commands.command()
    async def binary(self, ctx, encode_or_decode, string):
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            string = string.replace(" ", "")
            data = int(string, 2)
            decoded = data.to_bytes((data.bit_length() + 7) // 8, 'big').decode()
            await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            encoded = bin(int.from_bytes(string.encode(), 'big')).replace('b', '')
            await ctx.send(encoded)

    @commands.command()
    async def hex(self, ctx, encode_or_decode, string):
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            string = string.replace(" ", "")
            decoded = binascii.unhexlify(string).decode('ascii')
            await ctx.send(decoded)
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            byted = string.encode()
            encoded = binascii.hexlify(byted).decode('ascii')
            await ctx.send(encoded)

    @commands.command()
    async def url(self, ctx, encode_or_decode, message):
        if encode_or_decode == 'decode' or encode_or_decode == 'd':
            
            if '%20' in message:
                message = message.replace('%20', '(space)')
                await ctx.send(urllib.parse.unquote(message))
            else:
                await ctx.send(urllib.parse.unquote(message))
        
        if encode_or_decode == 'encode' or encode_or_decode == 'e':
            await ctx.send(urllib.parse.quote(message))

def setup(bot):
    bot.add_cog(EncodingDecoding(bot))