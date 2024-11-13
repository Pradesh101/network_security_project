from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet


def main_screen():


    # Function to generate a new symmetric key
    def generate_key():
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

    # Function to load an existing symmetric key from file
    def load_key():
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
        return key

    def reset():
        msg1.delete(1.0,END)

    # Function to encrypt a message
    def encrypt_message():
        fernet = Fernet(key)
        if fernet != "":

            screen1=Toplevel(screen)
            screen1.title("Encryption")
            screen1.geometry("400x250")
            screen1.configure(bg="#ed3833")
            
            message=msg1.get(1.0,END)

            encrypted_message = fernet.encrypt(message.encode())
            Label(screen1,text="Encrypt",font="arial",fg="white",bg="#ed3833").place(x=10,y=10)
            msg2 = Text(screen1,font="Robote 20", bg="white",relief=GROOVE,wrap=WORD,bd=0)
            msg2.place(x=10,y=40,width=380,height=170)
            msg2.insert(END,encrypted_message)


        elif fernet=="":
            messagebox.showerror("Encrytpion","Key error")

    # Function to decrypt a message
    def decrypt_message():
        fernet = Fernet(key)
        if fernet != "":

            screen2=Toplevel(screen)
            screen2.title("Decryption")
            screen2.geometry("400x250")
            screen2.configure(bg="#00bd56")
            
            encrypted_message=msg1.get(1.0,END)

            decrypted_message = fernet.decrypt(encrypted_message).decode()
            
            Label(screen2,text="Decrypt",font="arial",fg="white",bg="#00bd56").place(x=10,y=10)
            msg3 = Text(screen2,font="Robote 20", bg="white",relief=GROOVE,wrap=WORD,bd=0)
            msg3.place(x=10,y=40,width=380,height=170)
            msg3.insert(END,decrypted_message)

        elif fernet=="":
            messagebox.showerror("Decrytpion","Key error")

    if __name__ == "__main__":
    # Generate and save a key if not already saved
        try:
            key = load_key()
            print("Key loaded successfully.")
        except FileNotFoundError:
            key = generate_key()
            print("New key generated and saved.")



    screen= Tk()
    screen.geometry("375x398")
    screen.title("Symmetric Key Crptography")
        
    Label(text = "Enter message for encrption", fg="black", font=("calbri",13)).place(x=10,y=10)
    msg1 = Text(font="Robote 20", bg="white",relief=GROOVE,wrap=WORD,bd=0)
    msg1.place(x=10,y=50,width=355,height=100)

    Button(text="Encrypt", height="2",width=23,bg="#ed3833",fg="white",bd=0,command=encrypt_message).place(x=10,y=180)
    Button(text="Decrypt", height="2",width=23,bg="#00bd56",fg="white",bd=0,command=decrypt_message).place(x=200,y=180)
    Button(text="Reset", height="2",width=50,bg="#1089ff",fg="white",bd=0,command=reset).place(x=10,y=230)
    

    screen.mainloop()

main_screen()




    
    
