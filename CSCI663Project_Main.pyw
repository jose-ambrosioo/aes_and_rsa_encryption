######## INFORMATION ############################################################
#                                                                               #
# CSCI663G VA                                                                   #
# Fall 2023                                                                     #
# Instructor: Dr. Hong Zeng                                                     #
# Contributors to this file:                                                    #
# - Gilberto Andrés Guerra González (EncryptDecryptWinodw class, most other     #
#   tkinter code)                                                               #
# - José Nazareno Torres Ambrósio (AES with GUI integration, AES steps          #
#   including round keys shown in GUI, Text Files with GUI integration          #
#                                                                               #
#################################################################################


import logging
import time
from tkinter import *
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import os

logging.basicConfig(level=logging.CRITICAL,
                    format=' %(asctime)s -  %(levelname)s -  %(message)s')


# RSA implemented by Gilberto Andrés Guerra González
try:
    import CSCI663Project_RSA as rsa
except Exception as e:
    logging.critical(e)
    exit(1)

# AES implemented by José Nazareno Torres Ambrósio
try:
    import CSCI663Project_AES as aes
except Exception as e:
    logging.critical(e)
    exit(1)


# simple class that is only to circumvent not being able to get return value from tkinter button command function
class RSAParameterGenerator:
    def __init__(self):
        self.n, self.public_key, self.private_key = rsa.generate_keys(512)

    def get_keys(self):
        return (self.n, self.public_key, self.private_key)

    def generate_new_keys(self, pqlength):
        self.n, self.public_key, self.private_key = rsa.generate_keys(pqlength)

# read-only text boxes for various keys and outputs

class ReadOnlyText(Text):
    def __init__(self, root):
        Text.__init__(self, root, height=3)
        self.config(state=DISABLED)

    def replace(self, text):
        self.config(state=NORMAL)
        self.delete('1.0', END)
        self.insert('end', text)
        self.config(state=DISABLED)


class EncryptDecryptWindow(Frame):
    #
    # root: tkinter toplevel/root window
    #
    # ----------------------------------------------------------------
    # encrypt: encryption/decryption function
    #  this function will be passed:
    #  - plaintext/ciphertext
    #  - dictionary of keys; textbox labels/values (see below) or defaults
    #  - dictionary of options; group variable, chosen value (see below)
    #
    # ----------------------------------------------------------------
    # keys: array of strings, textboxes will be created and labeled for each
    #  example:
    #  ['n', 'e']
    #
    #  will produce this in UI:
    #    +----------+
    #  n |          |
    #    |          |
    #    +----------+
    #    +----------+
    #  e |          |
    #    |          |
    #    +----------+
    #
    #  and if user inputs 221 and 11, this is what will be passed to encryption function as mentioned above:
    #  {
    #    'n': '221',
    #    'e': '11'
    #  }
    #
    # ----------------------------------------------------------------
    # options: dictionary of dictionaries which will have radio button variables/values as keys and radio button text as values
    #  example:
    #  {
    #    'options1': {
    #      'a': 'single encryption',
    #      'b': 'double encryption'
    #    },
    #    'options2': {
    #      'c': 'something',
    #      'd': 'something else'
    #    }
    #  }
    #
    #  will produce radio buttons like this:
    #  ○ single encryption
    #  ○ double encryption
    #
    #  ○ something
    #  ○ something else
    #
    #  and if the user selects "double encryption" and "something", this is what will be passed to encryption function as mentioned above:
    #  {
    #    'options1': 'b',
    #    'options2': 'c'
    #  }
    #
    # ----------------------------------------------------------------
    # displayDefaults: whether or not to give user option of using pre-existing key(s)
    #
    # ----------------------------------------------------------------
    # defaultKeys: array of default keys to be displayed, must be as long as keys array
    #
    # ----------------------------------------------------------------
    # allowSelectFiles: whether user can put in files for input/output or not
    #
    # ----------------------------------------------------------------
    # encoding: encoding type, such as latin-1 (used for aes) or utf-8 (used for rsa), to read/write files with
    #
    # ----------------------------------------------------------------
    # buttonText: what is displayed on button
    #
    #
    #
    def __init__(self, root, encrypt, keys, options, displayDefaults, defaultKeys, allowSelectFiles, encoding, buttonText):
        super().__init__()

        if displayDefaults and len(keys) != len(defaultKeys):
            logging.warning(
                'number of keys to be inputted and number of default keys are unequal')
            # default key boxes will just have -
            defaultKeys = [*'-'*len(keys)]

        # column 0: textbox labels
        # column 1: text inputs/outputs
        # column 2: file inputs/outputs
        # column 3: extra space, only used for aes
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=3)
        self.columnconfigure(2, weight=2)
        self.columnconfigure(3, weight=2)

        def chooseFile(targetVariable):
            logging.info('file selection window opened')
            thefilename = filedialog.askopenfilename(
                initialdir='./', title='Select file...')
            targetVariable.set(thefilename)
            logging.info(f'file chosen: {thefilename}')

        Frame.__init__(self, root)

        # 0 = default keys, 1 = input keys
        keyChoice = StringVar(self, '0')
        if not displayDefaults:
            keyChoice.set('1')

        row_num = 0

        # allow user to select default keys

        if displayDefaults:
            Radiobutton(self, text='Last generated keys',
                        variable=keyChoice, value='0').grid(row=row_num, column=1, pady=10)
            row_num += 1
            for label, key in zip(keys, defaultKeys):
                logging.info(f'creating text box for default key {label}')
                Label(self, text=label).grid(row=row_num, column=0)
                keyBox = ReadOnlyText(self)
                keyBox.replace(key)
                keyBox.grid(row=row_num, column=1, pady=5)
                row_num += 1
            Radiobutton(self, text='Input keys',
                        variable=keyChoice, value='1').grid(row=row_num, column=1, pady=10)
            row_num += 1

            separator = ttk.Separator(self, orient='horizontal')
            separator.grid(row=row_num, column=0, columnspan=4, sticky='we', pady=8)
            row_num += 1

        # keys

        keyBoxes = {}
        keyFiles = {}
        keyChoices = {}

        

        for label in keys:
            if allowSelectFiles:
                keyChoices[label] = StringVar(self, 'string')
                keyFiles[label] = StringVar(self, '')
                Radiobutton(self, text='Enter key in text box',
                            variable=keyChoices[label], value='string').grid(row=row_num, column=1)
                Radiobutton(self, text='Read key from file', variable=keyChoices[label], value='file').grid(
                    row=row_num, column=2)
                row_num += 1

                def choose_key_file(label):
                    chooseFile(keyFiles[label])
                    logging.info(
                        f'reading from file {keyFiles[label].get()} to key {label}')

                Button(self, text=f'Select file for key {label}...', command=(
                    lambda label=label: choose_key_file(label))).grid(row=row_num, column=2, ipadx=4, ipady=4)

            Label(self, text=label).grid(row=row_num, column=0)
            keyBox = Text(self, height=3)
            keyBox.grid(row=row_num, column=1, pady=10)
            keyBoxes[label] = keyBox
            row_num += 1

        separator = ttk.Separator(self, orient='horizontal')
        separator.grid(row=row_num, column=0, columnspan=4, sticky='we', pady=8)
        row_num += 1

        # input box

        inputSource = StringVar(self, 'string')
        inputFile = StringVar(self, '')
        if allowSelectFiles:
            Radiobutton(self, text='Enter text in text box',
                        variable=inputSource, value='string').grid(row=row_num, column=1)
            Radiobutton(self, text='Read text from file',
                        variable=inputSource, value='file').grid(row=row_num, column=2)
            row_num += 1
            Button(self, text='Select file...', command=(lambda: chooseFile(
                inputFile))).grid(row=row_num, column=2, ipadx=4, ipady=4)

        Label(self, text='Input').grid(row=row_num, column=0)
        input_text = Text(self, height=3)
        input_text.grid(row=row_num, column=1, pady=15)

        row_num += 1

        separator = ttk.Separator(self, orient='horizontal')
        separator.grid(row=row_num, column=0, columnspan=4, sticky='we', pady=8)
        row_num += 1

        # options
        optionChoices = {}
        optionSubframes = {}
        for (var, choices) in options.items():
            optionChoices[var] = StringVar(self, list(choices.keys())[0])
            optionSubframes[var] = Frame(self)
            optionSubframes[var].grid(row=row_num, column=1)
            for (internal, external) in choices.items():
                Radiobutton(optionSubframes[var], text=external,
                            variable=optionChoices[var], value=internal).pack(side=TOP)
            row_num += 1

        if options:
            separator = ttk.Separator(self, orient='horizontal')
            separator.grid(row=row_num, column=0, columnspan=4, sticky='we', pady=8)
            row_num += 1


        # main button


        # get all keys as strings, from files and/or textboxes
        def getKeys():
            if keyChoice.get() == '1':
                result = {}
                for key in keys:
                    if allowSelectFiles and keyChoices[key].get() == 'file':
                        file = keyFiles[key]
                        #print(f'attempting to open file for key {key}')
                        f = open(file.get())
                        #print(f'printing f: {f}')
                        result[key] = f.read().strip()
                        #print(result[key])
                        f.close()
                    else:
                        result[key] = keyBoxes[key].get(1.0, END).strip()
            else:
                result = {}
                for (name, key) in zip(keys, defaultKeys):
                    result[name] = key
            #print(result)
            return result

        # gather options as dictionary
        def getOptions():
            result = {}
            for var in options.keys():
                result[var] = optionChoices[var].get()
            return result

        # get input as string from file/textbox
        def getInput():
            if inputSource.get() == 'string':
                return input_text.get(1.0, END).strip()
            else:
                f = open(inputFile.get(), encoding=encoding)
                txt = f.read()
                f.close()
                #print(txt)
                return txt

        # write output to file/textbox
        def writeOutput(txt):
            if outputTarget.get() == 'string':
                output_text.replace(txt)
            else:
                f = open(outputFile.get(), 'w', encoding=encoding)
                f.write(str(txt))
                #print(txt)
                f.close()

        Button(self, text=buttonText, command=(lambda: writeOutput(encrypt(
            getInput(), getKeys(), getOptions(), extraFrame)))).grid(row=row_num, column=1, ipadx=4, ipady=4, pady=10)
        row_num += 1

        separator = ttk.Separator(self, orient='horizontal')
        separator.grid(row=row_num, column=0, columnspan=4, sticky='we', pady=8)
        row_num += 1

        # output box

        outputTarget = StringVar(self, 'string')
        outputFile = StringVar(self, '')
        if allowSelectFiles:
            Radiobutton(self, text='Put text in text box', variable=outputTarget,
                        value='string').grid(row=row_num, column=1)
            Radiobutton(self, text='Write text to file', variable=outputTarget,
                        value='file').grid(row=row_num, column=2)
            row_num += 1
            Button(self, text='Select file...', command=(lambda: chooseFile(
                outputFile))).grid(row=row_num, column=2, ipadx=4, ipady=4)

        Label(self, text='Output').grid(row=row_num, column=0)
        output_text = ReadOnlyText(self)
        output_text.grid(row=row_num, column=1, pady=15)
        row_num += 1

        # frame for other algorithm output
        extraFrame = Frame(self)
        extraFrame.grid(row=0, rowspan=row_num, column=3, sticky='n')


rsa_security_levels = {
    '80 bit': 1024,
    '128 bit': 3072,
    # anything longer takes too long when generating primes...
    # '192': 7680,
    # '256': 15360,
}

rsa_params = RSAParameterGenerator()


# # Define a function to clear the input text
# def clearToTextInput(aes_steps_text):
#     aes_steps_text.delete("1.0", END)


def open_aes_encrypt(root):
    aes_string_message_encrypt = Toplevel(root)

    def encrypt(plaintext, keys, options, extraFrame):
        for widget in extraFrame.winfo_children():
            widget.destroy()
        
        password = keys['Password'].strip()

        aes_encrypt_string = aes.encrypt_string(plaintext, password, [])

        aes_steps = list(aes_encrypt_string[1:])

        # Add a Scrollbar(horizontal)
        v = Scrollbar(extraFrame, orient='vertical')
        v.pack(side=RIGHT, fill='y')

        aes_steps_text = Text(extraFrame, wrap="word", width=60,
                              height=30, yscrollcommand=v.set)

        # clearToTextInput(aes_steps_text)

        for i in aes_steps:
            # line = "".join(str(i))
            # aes_steps_text.insert(END, line + "\n")
            # aes_steps_text.insert(END, str(i))
            aes_steps_text.insert(END, aes_steps)

            v.config(command=aes_steps_text.yview)
            aes_steps_text.pack(side=TOP, padx=3, pady=3)

        return aes_encrypt_string[0]

    aesFrame = EncryptDecryptWindow(
        aes_string_message_encrypt, encrypt, ['Password'], {}, False, [], True, 'latin-1', 'Encrypt')
    aesFrame.pack(padx=20, pady=20)


def open_aes_decrypt(root):
    aesWindow = Toplevel(root)

    def decrypt(ciphertext, keys, options, extraFrame):
        for widget in extraFrame.winfo_children():
            widget.destroy()
        
        password = keys['Password'].strip()

        aes_decrypt_string = aes.decrypt_string(ciphertext, password, [])

        aes_steps = list(aes_decrypt_string[1:])

        # Add a Scrollbar(horizontal)
        v = Scrollbar(extraFrame, orient='vertical')
        v.pack(side=RIGHT, fill='y')

        aes_steps_text = Text(extraFrame, wrap="word", width=60,
                              height=30, yscrollcommand=v.set)

        for i in aes_steps:
            aes_steps_text.insert(END, aes_steps)

            v.config(command=aes_steps_text.yview)
            aes_steps_text.pack(side=TOP, padx=3, pady=3)

        return aes_decrypt_string[0]

    aesFrame = EncryptDecryptWindow(
        aesWindow, decrypt, ['Password'], {}, False, [], True, 'latin-1', 'Decrypt')
    aesFrame.pack(padx=20, pady=20)


def open_rsa_keys(root):
    rsaRoot = Toplevel(root)
    rsaRoot.title('RSA')

    rsaWindow = Frame(rsaRoot)
    rsaWindow.pack(padx=20, pady=20)

    def new_keys(output_box, n_length):
        rsa_params.generate_new_keys(n_length // 2)
        readonly.config(state=NORMAL)
        readonly.delete(1.0, END)
        readonly.insert(
            'end', f'n: {rsa_params.n}\n\nPublic key: {rsa_params.public_key}\n\nPrivate key: {rsa_params.private_key}')
        readonly.config(state=DISABLED)

    security_level = StringVar(rsaWindow)
    security_level.set('80 bit')

    OptionMenu(rsaWindow, security_level, *rsa_security_levels).pack(side=TOP)

    readonly = Text(rsaWindow)
    readonly.delete(1.0, END)
    readonly.insert(
        'end', f'n: {rsa_params.n}\n\nPublic key: {rsa_params.public_key}\n\nPrivate key: {rsa_params.private_key}')
    readonly.pack(side=TOP)
    readonly.config(state=DISABLED)

    Button(rsaWindow, text='Generate new RSA parameters', command=(lambda: new_keys(
        readonly, rsa_security_levels[security_level.get()]))).pack(side=BOTTOM)

    # new_keys(readonly, 1024)


def open_rsa_encrypt(root):
    rsaWindow = Toplevel(root)
    def_n, def_e, _ = rsa_params.get_keys()

    def encrypt(plaintext, keys, options, _):
        if not (keys['n'].isdigit() and keys['e'].isdigit()):
            return 'keys are not numerical'
        n = int(keys['n'])
        e = int(keys['e'])

        if options['encode'] == '1' and not plaintext.isdigit():
            return 'message is not an integer'

        return rsa.encrypt(plaintext, n, e, options['encode'] == '1')

    rsaFrame = EncryptDecryptWindow(rsaWindow, encrypt, ['n', 'e'], {'encode': {
                                    '0': 'Convert message to bytes and then integer in little-endian order', '1': 'Message is already integer'}}, True, [str(def_n), str(def_e)], True, 'utf-8', 'Encrypt')
    rsaFrame.pack(padx=20, pady=20)


def open_rsa_decrypt(root):
    rsaWindow = Toplevel(root)
    def_n, _, def_d = rsa_params.get_keys()

    def decrypt(ciphertext, keys, options, _):
        if not (keys['n'].isdigit() and keys['d'].isdigit()):
            return 'keys are not numerical'
        n = int(keys['n'])
        d = int(keys['d'])

        if not ciphertext.isdigit():
            return 'ciphertext is not an integer'

        try:
            return rsa.decrypt(int(ciphertext), n, d, options['decode'] == '1')
        except UnicodeDecodeError as e:
            return f'ERROR: {e}\n\nPerhaps you should select the \'Keep message as integer\' option, or you inputted the wrong keys?'

    rsaFrame = EncryptDecryptWindow(rsaWindow, decrypt, ['n', 'd'], {'decode': {
                                    '0': 'Convert decrypted message integer to bytes in little-endian order, then to string', '1': 'Keep message as integer'}}, True, [str(def_n), str(def_d)], True, 'utf-8', 'Decrypt')
    rsaFrame.pack(padx=20, pady=20)


root = Tk()

mainWindow = Frame(root)
mainWindow.pack(padx=40, pady=20)

Button(mainWindow, text='AES - Encrypt', command=(lambda: open_aes_encrypt(root))
       ).pack(fill=X, ipadx=4, ipady=4, pady=4)
Button(mainWindow, text='AES - Decrypt', command=(lambda: open_aes_decrypt(root))
       ).pack(fill=X, ipadx=4, ipady=4, pady=4)
Button(mainWindow, text='RSA - Generate keys',
       command=(lambda: open_rsa_keys(root))).pack(fill=X, ipadx=4, ipady=4, pady=4)
Button(mainWindow, text='RSA - Encrypt', command=(lambda: open_rsa_encrypt(root))
       ).pack(fill=X, ipadx=4, ipady=4, pady=4)
Button(mainWindow, text='RSA - Decrypt', command=(lambda: open_rsa_decrypt(root))
       ).pack(fill=X, ipadx=4, ipady=4, pady=4)
# Button(mainWindow, text='Test\nRSA - Encrypt', command=( lambda: open_wip_class_window(root) )).pack(fill=X, ipadx=4, ipady=4, pady=4)
root.title('CSCI663G VA - Fall 2023')

root.mainloop()
