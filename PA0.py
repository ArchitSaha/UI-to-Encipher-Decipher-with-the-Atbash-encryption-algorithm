#Section-1 : defining function for encryption#
def Artencipher(plaintext):
    ciphertext = ""
    for c in range(len(plaintext)):
        char = plaintext[c]
        if (char.isupper()):
            ciphertext += chr(90-(ord(char)-65) % 26)
        elif char==" ":
            ciphertext += " "
        elif (char.islower()):
            ciphertext += chr(122-(ord(char)-97)%26)
        else:
            ciphertext += char
    return ciphertext

#Section-2 : defining function for decryption#
def Artdecipher(ciphertext):
    plaintext = ""
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if (char.isupper()):
            plaintext += chr(90-(ord(char)-65) % 26)
        elif char==" ":
            plaintext += " "
        elif (char.islower()):
            plaintext += chr(122-(ord(char)-97)%26)
        else:
            plaintext += char
    return plaintext
# modules to import
import tkinter as tk
from tkinter import ttk, Button, Entry

#Section-3 : tkinter labels, functions for buttons, etc#
class ArtCipher:

    def __init__(self, root):

        self.plain_text = tk.StringVar(root, value="")
        self.cipher_text = tk.StringVar(root, value="")
        self.key = tk.IntVar(root)
# creates Tkinter window
        # creating root object 
        #root = Tk() 
  
# defining size of window 
        #root.geometry("1200x6000") 
        # creates window title
        root.title("Cipher PA0 Application")
        # allows for window to be resized
        root.resizable(True,True)
         # window background
        root.configure(background='gold')
       
        style = ttk.Style() 
        style.configure("TLabel", font = "Serif 20", padding=20)
        style.configure("TButton", font="Serif 10", padding=5)
        style.configure("TEntry", font="Serif 36", padding=20)

        self.plain_label = tk.Label(root, text="Plain text", fg="green",font = ('arial', 12, 'bold'), 
		 bd = 16, anchor = "w").grid(row=1, column=1)
# seperated the .grid as it was causing a None type error
        self.plain_entry = tk.Entry(root,font = ('arial', 16, 'bold'), textvariable = 'Msg', bd = 10, insertwidth = 4, bg = "powder blue", justify = 'right',width=32)
        self.plain_entry.grid(row=2, column=0, rowspan=2 , columnspan=2)
        self.plain_clear = tk.Button(root, text="Clear",fg="brown",
                                    command=lambda: self.clear('plain')).grid(row=4, column=1)


# buttons to encrypt / decrypt
        self.encipher_button = Button(root, text="Encrypt ->",
                                    command=lambda: self.encipher_press()).grid(row=2, column=3)
        self.decipher_button = Button(root, text="<- Decrypt",
                                    command=lambda: self.decipher_press()).grid(row=3, column=3)

        self.cipher_label = tk.Label(root, text="Cipher text", fg="red",font = ('arial', 12, 'bold'), 
		 bd = 16, anchor = "w").grid(row=1, column=4)

        self.cipher_entry = Entry(root,
                                    font = ('arial', 16, 'bold'), 
			textvariable = "Result", bd = 10, insertwidth = 4, 
					bg = "powder blue", justify = 'left',width=32)
        self.cipher_entry.grid(row=2, column=4, rowspan=2 , columnspan=2)

        self.cipher_clear = tk.Button(root, text="Clear",fg="brown",
                                    command=lambda: self.clear('cipher')).grid(row=4, column=4)



    def clear(self, str_val):
        if str_val == 'cipher':
            self.cipher_entry.delete(0, 'end')
        else:
            self.plain_entry.delete(0, 'end')

    def encipher_press(self):
        cipher_text = Artencipher(self.plain_entry.get())
        self.cipher_entry.delete(0, "end")
        self.cipher_entry.insert(0, cipher_text)

    def decipher_press(self):
        plain_text = Artdecipher(self.cipher_entry.get())
        self.plain_entry.delete(0, "end")
        self.plain_entry.insert(0, plain_text)

#making window alive
root = tk.Tk()
Art = ArtCipher(root)
root.mainloop()
