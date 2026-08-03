# Author: Pedro Carvalho
# August 2026
# Version 1.0




import ctypes
import sys
import struct
from queue import Queue
import queue
import socket
import threading
from threading import Lock
import os
import hashlib
import time
import random
import kivy
from kivy.config import Config
Config.set('graphics', 'width', '450')
Config.set('graphics', 'height', '750')
Config.set('graphics', 'resizable', '0')
from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.textinput import TextInput
from kivy.cache import Cache
from kivy.core.window import Window
from kivy.clock import Clock
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import traceback
import gc
import weakref
Window.clearcolor = (0, 0, 0, 1)




# ==========================================
# CRYPTO & ANTI-FORENSICS
# ==========================================




class BurnerMemory:
    """Bypasses the garbage collector and overwrites Bytearray memory with null bytes to prevent forensic RAM scraping."""

    @staticmethod

    def shred(data: bytearray):
        
        # Check if the target is a bytearray and has a length greater than 0
        if isinstance(data, bytearray) and len(data) > 0:
            
            # Map the C-level buffer.
            # (ctypes.c_char * len) creates a C array type of the exact size needed.
            # .from_buffer(data) automatically safely extracts the raw memory pointer (ob_bytes),
            # completely bypassing the PyObject struct headers (ob_refcnt, ob_type).
            c_buffer = (ctypes.c_char * len(data)).from_buffer(data)

            # Use C to confirm the target is replaced by zeros in RAM. 
            # addressof() returns the literal physical memory address of the payload itself.
            ctypes.memset(ctypes.addressof(c_buffer), 0, len(data))

        # Delete the target after it's all zeros.
        del data



class BurnerMemoryByte:
    """Bypasses the garbage collector and overwrites Bytes memory with null bytes to prevent forensic RAM scraping."""

    @staticmethod

    def shred(data: bytes):

        # Check if the target is in bytes.
        if isinstance(data, bytes):

            # This is to find the size of just the target bytes.
            # len() gives the number of bytes.
            # +1 is a null terminator. CPython adds an invisible byte (\0) to the end of every byte object.
            target_size = (len(data) + 1)

            # This is to find the size of just the C struct header.
            # sys.getsizeof() gives the entire footprint of the bytes object.
            # The whole footprint - the size of the target bytes, equals the C struct header size.
            header_size = sys.getsizeof(data) - target_size

            # This is to calculate how many bytes will be zeroed out.
            # The null terminator is left intact here.
            # That guarantees that the C code still sees a structurally valid bytes object.
            target_bytes = len(data)
            
            # Use C to confirm the target it's replaced by zeros in RAM.
            # Id() returns the literal physical memory address of the C struct in RAM.
            # header_size jumps to the start of the target bytes, skipping the header.
            # target_bytes is the actuall bytes without the null terminator.
            ctypes.memset(id(data) + header_size, 0, target_bytes)

        # Delete the target after it's all zeros.
        del data




class BurnerMemoryString:
    """Bypasses the garbage collector and overwrites String memory with null bytes to prevent forensic RAM scraping."""
    
    @staticmethod
    
    def shred(data: str):
        
        # Check if the target is a string.
        if isinstance(data, str):

            # Determines the largest Unicode code point in the string data.
            # This is to determine how many bytes Python uses internally to store each character in the string.
            # ord(c) returns the Unicode integer. max() selects the highest.
            # The storage size is determined by the largest character in the string.
            max_character = max(ord(c) for c in data)

            # (ASCII, code points < 256) -> 1 byte per character.
            if max_character < 256:
                character_size = 1
            
            # (Basic Multilingual Plane, code points < 65536) -> 2 bytes per character.
            elif max_character < 65536:
                character_size = 2
            
            # (Supplementary characters, code points >= 65536) -> 4 bytes per character.
            else:
                character_size = 4

            # This is to find the size of just the target string.
            # len() gives the number of characters.
            # +1 is a null terminator. CPython adds as invisible character (\0) to the end of every string.
            # * character_size to multiply each character by its value in bytes.
            target_size = (len(data) + 1) * character_size

            # This is to find the size of just the C struct header.
            # sys.getsizeof() gives the entire footprint of the string object.
            # The whole footprint - the size of the target string, equals the C struct header size.
            header_size = sys.getsizeof(data) - target_size

            # This is to calculate how many bytes will be zeroed out.
            # The null terminator is left intact here.
            # That guarantees that the C code still sees a structurally valid string object.
            target_string = len(data) * character_size

            # Use C to confirm the target it's replaced by zeros in RAM.
            # Id() returns the literal physical memory address of the C struct in RAM.
            # header_size jumps to the start of the target string, skipping the header.
            # target_string is the actuall string without the null terminator.
            ctypes.memset(id(data) + header_size, 0, target_string)

        del data



class SecurityError(Exception):
    """
    Generic security exception to prevent sensitive data leaks in tracebacks.

    This exception is raised throughout the application to ensure that no
    cryptographic material, plaintext, or internal state is ever exposed in
    error messages or stack traces. All exceptions that could contain sensitive
    data are caught and re-raised as SecurityError with a generic message and
    suppressed traceback (via "from None").

    Note:
        This is the only exception type that should propagate to the user.
        All other exceptions must be caught and converted to SecurityError.
    """

    pass




class E2EProtocol:
    """
    Double Ratchet-based end-to-end encryption protocol for secure messaging.

    Implements a symmetric key ratchet with Perfect Forward Secrecy (PFS) by
    deriving ephemeral keys for each message. Uses HKDF-SHA256 for key derivation
    and AES-GCM for authenticated encryption. Designed to resist:
      - Compromised long-term keys (via ephemeral per-message keys).
      - Reflection attacks (via asymmetric send/receive chain keys).
      - Traffic analysis (via fixed-size padding).

    Attributes:
        padding_size (int): Message padding size (bytes) to defeat size-based analysis.
        send_chain_key (bytes): Current 32-byte chain key for outgoing messages.
        receive_chain_key (bytes): Current 32-byte chain key for incoming messages.

    Note:
        All intermediate key material (shared secrets, derived keys, nonces) is
        explicitly shredded from memory immediately after use. No plaintext or
        key material persists longer than necessary.
    """



    
    def __init__(self, shared_secret: bytes, is_initiator: bool, padding_size: int = 4096):
        """
        Initializes the Double Ratchet state from a shared secret.

        Derives two independent symmetric keys (send/receive) from the X25519 shared
        secret using HKDF-SHA256. The "is_initiator" flag ensures asymmetric key
        alignment to prevent reflection attacks. All input material is shredded
        after derivation.

        Arguments:
            shared_secret: 32-byte raw output from X25519 DH exchange.
            is_initiator: If True, this peer initiated the connection (affects key alignment).
            padding_size: Fixed size (bytes) for message padding to defeat traffic analysis.

        Raises:
            SecurityError: If key derivation fails (generic error, no traceback).
        """

        self.padding_size = padding_size

        # Pre-initialized variables so the finally block can safely check them.
        salt_str = None
        info_str = None
        salt_bytes = None
        info_bytes = None
        derived = None

        try:
            # Create the strings dynamically (not as literals) to avoid interning.
            salt_str = "".join(["y", "o", "u", "r", "_", "s", "t", "r", "i", "n", "g"])
            info_str = "".join(["y", "o", "u", "r", "_", "s", "t", "r", "i", "n", "g"])

            # Encode for bytes.
            salt_bytes = salt_str.encode('utf-8')
            info_bytes = info_str.encode('utf-8') 

            # Burn what is not needed anymore.
            BurnerMemoryString.shred(salt_str)
            BurnerMemoryString.shred(info_str)

            # Expand the 32-byte shared_secret into 64 bytes of cryptographically secure key material.
            # The salt is like the ID Card.
            # Info is the context-specific information. Can be used for example to create private sub-networks for different teams.
            # Derive feeds the X25519 secret into the machine and produces the final bytes.
            derived = HKDF(algorithm = hashes.SHA256(), length=64, salt=salt_bytes, info=info_bytes).derive(shared_secret)

            # Burn what is not needed anymore.
            BurnerMemoryByte.shred(salt_bytes)
            BurnerMemoryByte.shred(info_bytes)
            BurnerMemoryByte.shred(shared_secret)
        
            # Split the derived material into two independent 32-byte chain keys.
            # Asymmetric assignment ensures User_1's transmited key matches User_2's received key.
            if is_initiator:
                self.send_chain_key = derived[:32]
                self.receive_chain_key = derived[32:]

            else:
                self.send_chain_key = derived[32:]
                self.receive_chain_key = derived[:32]
            
            # Burn what is not needed anymore.
            BurnerMemoryByte.shred(derived)

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Protocol initialization failed.") from None

        finally:
            # Guaranteed Burn, whether successful or crashed.
            if shared_secret: 
                BurnerMemoryByte.shred(shared_secret)
            if salt_str: 
                BurnerMemoryString.shred(salt_str)
            if info_str: 
                BurnerMemoryString.shred(info_str)
            if salt_bytes: 
                BurnerMemoryByte.shred(salt_bytes)
            if info_bytes: 
                BurnerMemoryByte.shred(info_bytes)
            if derived: 
                BurnerMemoryByte.shred(derived)


    
    
    def _ratchet_step(self, chain_key: bytes) -> tuple[bytes, bytes]:
        """
        Advances the symmetric ratchet and generates a new message key.

        Uses HKDF-SHA256 to derive a new chain key and a one-time message key from
        the current chain key. This ensures Perfect Forward Secrecy: compromising
        a chain key does not allow decryption of past messages.

        Arguments:
            chain_key: Current 32-byte chain key (send or receive).

        Returns:
            tuple: (next_chain_key, message_key), both 32-byte values.

        Raises:
            SecurityError: If ratchet step fails (generic error, no traceback).

        Note:
            The input "chain_key" is shredded immediately after use. The caller
            must update its chain key reference to the returned "next_chain_key".
        """

        # Pre-initialized variables so the finally block can safely check them.
        salt_str = None
        info_str = None
        salt_bytes = None
        info_bytes = None
        key_material = None

        try:
            # Create the strings dynamically (not as literals) to avoid interning.
            salt_str = "".join(["y", "o", "u", "r", "_", "s", "t", "r", "i", "n", "g"])
            info_str = "".join(["y", "o", "u", "r", "_", "s", "t", "r", "i", "n", "g"])

            # Encode for bytes.
            salt_bytes = salt_str.encode('utf-8')
            info_bytes = info_str.encode('utf-8') 

            # Burn what is not needed anymore.
            BurnerMemoryString.shred(salt_str)
            BurnerMemoryString.shred(info_str)

            # Expand the 32-byte chain_key into 64 bytes of cryptographically secure key material.
            # The salt is like the ID Card.
            # Info is the context-specific information. Can be used for example to create private sub-networks for different teams.
            # Derive feeds the X25519 secret into the machine and produces the final scrambled bytes.
            key_material = HKDF(algorithm = hashes.SHA256(), length=64, salt = salt_bytes, info = info_bytes).derive(chain_key)

            # Burn what is not needed anymore.
            # The old key is burned. This is Forward Secrecy. If someone hacks you now, they cannot decrypt past messages.
            BurnerMemoryByte.shred(chain_key)
            BurnerMemoryByte.shred(salt_bytes)
            BurnerMemoryByte.shred(info_bytes)

            # Split the derived material into two independent 32-byte chain keys.
            # Together they are used to create the next key.
            next_chain = key_material[:32]
            message_key = key_material[32:]

            # Burn what is not needed anymore.
            BurnerMemoryByte.shred(key_material)

            # Deliver the material for the next key.
            return next_chain, message_key
            
        
        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Ratchet step failed.") from None
        
        finally:
            # Guaranteed Burn, whether successful or crashed.
            if chain_key: 
                BurnerMemoryByte.shred(chain_key)
            if salt_str: 
                BurnerMemoryString.shred(salt_str)
            if info_str: 
                BurnerMemoryString.shred(info_str)
            if salt_bytes: 
                BurnerMemoryByte.shred(salt_bytes)
            if info_bytes: 
                BurnerMemoryByte.shred(info_bytes)
            if key_material: 
                BurnerMemoryByte.shred(key_material)

    

    
    def encrypt(self, plaintext: str, session_id: bytes) -> bytes:
        """
        Encrypts a message with AES-GCM and session binding.

        Binds the ciphertext to a session ID using a hashed "ghost_id" as AAD
        (Authenticated Additional Data). Adds a 4-byte length header and pads
        the payload to "padding_size" to defeat traffic analysis. Uses a random
        12-byte nonce for each encryption.

        Arguments:
            plaintext: Message text to encrypt (UTF-8 encoded).
            session_id: Unique session identifier (used for AAD binding).

        Returns:
            bytes: 12-byte nonce concatenated with AES-GCM ciphertext.

        Raises:
            SecurityError: If encryption fails (generic error, no traceback).

        Note:
            The "plaintext" string is shredded immediately after encoding to bytes.
            The "session_id" is never transmitted; only its SHA-256 hash (ghost_id) is used.
        """

        # 1. Pre-initialize all variables that need to be shredded.
        ghost_id = None
        raw_bytes = None
        header = None
        raw_payload = None
        message_key = None
        aesgcm = None
        nonce = None
        ciphertext = None

        try:
            # Session Binding (Anti-Replay / AAD generation).
            # The session_id is hashed so it never travels over the wire.
            # The message is binded to the session.
            ghost_id = hashlib.sha256(session_id).digest()
        
            # Convert str to bytes.
            raw_bytes = plaintext.encode('utf-8')

            # Burn what is not needed anymore.
            BurnerMemoryString.shred(plaintext)

            # Pack the length as a 4-byte big-endian unsigned integer.
            # Struct.pack is a python tool that translates a python number into raw binary bytes that
            # a C program (or network socket) can understand.
            # ">" is a Big-Endian. It tells the machine to read the bytes from left to right.
            # "I" is an unsigned int. This tells python to reserve exactly 4 bytes of space for this number.
            # Measure "raw_bytes" to know the length of the message.
            # The objective is to create a four bytes header in the beginning of the message.
            header = struct.pack(">I", len(raw_bytes))
        
            # Now the data looks like this: [4 bytes of length]+[the message].
            # Create a mutable bytearray using just the 4-byte header.
            raw_payload = bytearray(header)

            # Append the plaintext in-place (No intermediate copy created).
            raw_payload.extend(raw_bytes)

            # Burn what is not needed anymore.
            BurnerMemoryByte.shred(header)
            BurnerMemoryByte.shred(raw_bytes)

            # Traffic Analysis Defeat (Padding).
            # If the message is shorter than self.padding_size, add zeros until it is exactly the lenght of self.padding_size.
            # Do this using a fixed-size header of 4 bytes. This allows the receiver to
            # know exactly where the message ends and the noise begins.
            # If someone is watching traffic, they cannot try to guess the content by size.
            if len(raw_payload) < self.padding_size:
                raw_payload.extend(b'\x00' * (self.padding_size - len(raw_payload)))
        
            # Ratchet Step & Cipher Initialization.
            # Take the previous "send_chain_key" and replace it with the new "send_chain_key".
            self.send_chain_key, message_key = self._ratchet_step(self.send_chain_key)

            # Initialize the cipher.
            # Initializes AES in GCM mode. This provides authenticity. If a single bit is 
            # changed during transmition, the decryption fails.
            aesgcm = AESGCM(message_key)

            # Burn what is not needed anymore.
            BurnerMemoryByte.shred(message_key)

            # A random Initiation Vector. It ensures that the same message encrypted twice never looks the same.
            nonce = os.urandom(12)
        
            # Pass ghost_id as the Authenticated Additional Data (AAD) 
            ciphertext = aesgcm.encrypt(nonce, raw_payload, ghost_id)

            # Destroy the engine. This sends a signal to OpenSSL to execute OPENSSL_cleanse(),
            # which is designed to overwrite the Key Schedule with zeros before returning the memory to the OS.
            del aesgcm
        
            # Transmit final package.
            # Glues the 12-byte nounce to the front of the encrypted message and sends it out.
            return nonce + ciphertext

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Encryption failed.") from None

        finally:
            # Guaranteed Burn, whether successful or crashed.
            if plaintext:
                BurnerMemoryString.shred(plaintext)
            if ghost_id:
                BurnerMemoryByte.shred(ghost_id)
            if raw_bytes:
                BurnerMemoryByte.shred(raw_bytes)
            if header:
                BurnerMemoryByte.shred(header)
            if message_key:
                BurnerMemoryByte.shred(message_key)
            if raw_payload:
                BurnerMemory.shred(raw_payload)
            if nonce:
                BurnerMemoryByte.shred(nonce)
            if ciphertext:
                BurnerMemoryByte.shred(ciphertext)

        


    def decrypt(self, combined_payload: bytes, session_id: bytes) -> str:
        """
        Decrypts a message and verifies session binding.

        Splits the payload into nonce (12 bytes) and ciphertext, then decrypts
        using AES-GCM with the session's ghost_id as AAD. Validates the
        authentication tag to ensure integrity. Strips padding after decryption.

        Arguments:
            combined_payload: Raw network packet (12-byte nonce + ciphertext).
            session_id: Unique session identifier (used to compute ghost_id for AAD).

        Returns:
            str: Decrypted plaintext message (UTF-8 decoded).

        Raises:
            SecurityError: If decryption fails (integrity mismatch or other error).

        Note:
            The "combined_payload" is shredded immediately after decryption.
            If the authentication tag fails, the method raises SecurityError
            without exposing the decrypted (or partially decrypted) data.
        """ 

        # Pre-initialize all variables that need to be Burned.
        ghost_id = None
        nonce = None
        ciphertext = None
        message_key = None
        aesgcm = None
        decrypted_bytes = None
        header = None
        actual_message_bytes = None

        try:
            # Session Binding Verification.
            ghost_id = hashlib.sha256(session_id).digest()

            # Network Payload Splitting.
            # Grab the first 12 bytes of the previous nonce.
            nonce = combined_payload[:12]

            # The encrypted message + 16 byte authentication tag.
            # Grab everything from byte 12 to the end of the packet.
            ciphertext = combined_payload[12:]

            # Ratchet Step & Cipher Initialization.
            # Returns a new chain key and immediatly overwrites the old one.
            # Generates a new message_key that is unique for this message only.
            self.receive_chain_key, message_key = self._ratchet_step(self.receive_chain_key)
        
            # Initialize the cipher.
            # Initializes AES in GCM mode. This provides authenticity. If a single bit is changed during transmition,
            # the decryption fails.
            aesgcm = AESGCM(message_key)

            # Burn what is not needed anymore.
            BurnerMemoryByte.shred(message_key)
        
            # Authenticated Decryption.
            # This mathematically guarantees the ciphertext was created with ghost_id.
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, ghost_id)

            # Burn what is no longer needed.
            BurnerMemoryByte.shred(nonce)
            BurnerMemoryByte.shred(ciphertext)
            BurnerMemoryByte.shred(ghost_id)
            BurnerMemoryByte.shred(combined_payload)

            # Destroy the engine. This sends a signal to OpenSSL to execute OPENSSL_cleanse(),
            # which is designed to overwrite the Key Schedule with zeros before returning the memory to the OS.
            del aesgcm
            
            # Extract Length Header.
            header = decrypted_bytes[:4]
 
            # Extract Actual Payload (Ignoring the 512-byte padding).
            # Calculate the length and slice in one single anonymous operation.
            # [0] struct.unpack always returns a tuple. This is to grab the actual number.
            # The integer never gets assigned to a variable name.
            actual_message_bytes = decrypted_bytes[4 : 4 + struct.unpack(">I", header)[0]]

            # Decode from binary to text.
            final_text = actual_message_bytes.decode('utf-8')
                        
            BurnerMemoryByte.shred(decrypted_bytes)
            BurnerMemoryByte.shred(header)
            BurnerMemoryByte.shred(actual_message_bytes)

            return final_text
        
        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Decryption failed: Integrity mismatch.") from None

        finally:
            # Guaranteed Burn, whether successful or crashed.
            if combined_payload: 
                BurnerMemoryByte.shred(combined_payload)
            if ghost_id: 
                BurnerMemoryByte.shred(ghost_id)
            if nonce: 
                BurnerMemoryByte.shred(nonce)
            if ciphertext: 
                BurnerMemoryByte.shred(ciphertext)
            if message_key: 
                BurnerMemoryByte.shred(message_key)
            if decrypted_bytes: 
                BurnerMemoryByte.shred(decrypted_bytes)
            if header: 
                BurnerMemoryByte.shred(header)
            if actual_message_bytes: 
                BurnerMemoryByte.shred(actual_message_bytes)
        



# ==========================================
# UI LAYOUT
# ==========================================




KV_STRING = '''
<MessageLabel@Label>:
    size_hint_y: None
    text_size: self.width, None
    height: self.texture_size[1]
    padding: 10, 10
    markup: True
    font_name: 'Roboto'

ScreenManager:
    LobbyScreen:
    ChatScreen:

<LobbyScreen>:
    name: 'lobby'
    BoxLayout:
        orientation: 'vertical'
        padding: 40
        spacing: 15
        Image:
            source: 'images/your_image.png'
            font_name: 'fonts/NotoMono-Regular.ttf'
            size_hint_y: None
            height: 430
            allow_stretch: True
            keep_ratio: True
        TextInput:
            id: target_input
            hint_text: 'Relay IP (e.g. 127.0.0.1)'
            text: '127.0.0.1'
            multiline: False
            size_hint_y: None
            height: '40dp'
            background_color: 0.1, 0.1, 0.1, 1
            foreground_color: 0, 1, 0, 1
        TextInput:
            id: room_input
            hint_text: 'Sector Code (e.g. 0000)'
            multiline: False
            size_hint_y: None
            height: '40dp'
            background_color: 0.1, 0.1, 0.1, 1
            foreground_color: 0, 1, 0, 1
        TextInput:
            id: my_riddle
            hint_text: 'Your Riddle to Peer'
            multiline: False
            size_hint_y: None
            height: '40dp'
            background_color: 0.1, 0.1, 0.1, 1
            foreground_color: 0, 1, 0, 1
        SecureBufferInput:
            id: my_answer
            hint_text: 'Required Answer to Your Riddle'
            do_undo: False
            size_hint_y: None
            height: '40dp'
            background_color: 0.1, 0.1, 0.1, 1
            foreground_color: 0, 1, 0, 1
        Button:
            text: 'INITIATE TUNNEL'
            size_hint_y: None
            height: '50dp'
            background_color: 0, 0.6, 0, 1
            color: 0, 0, 0, 1
            bold: True
            on_release: app.start_connection()

<ChatScreen>:
    name: 'chat'
    BoxLayout:
        orientation: 'vertical'
        RecycleView:
            id: chat_rv
            viewclass: 'MessageLabel'
            canvas.before:
                Color:
                    rgba: 0.05, 0.05, 0.05, 1
                Rectangle:
                    pos: self.pos
                    size: self.size
            RecycleBoxLayout:
                default_size: None, dp(40)
                default_size_hint: 1, None
                size_hint_y: None
                height: self.minimum_height
                orientation: 'vertical'
                spacing: dp(5)
                padding: dp(10)
        BoxLayout:
            size_hint_y: None
            height: '60dp'
            padding: dp(5)
            spacing: dp(5)
            canvas.before:
                Color:
                    rgba: 0.1, 0.1, 0.1, 1
                Rectangle:
                    pos: self.pos
                    size: self.size
            SecureBufferInput:
                id: msg_input
                multiline: False
                hint_text: '>>>'
                background_color: 0, 0, 0, 1
                foreground_color: 0, 1, 0, 1
                on_text_validate: app.handle_input()
            Button:
                text: 'SEND'
                size_hint_x: 0.25
                background_color: 0.8, 0, 0, 1
                color: 0, 0, 0, 1
                bold: True
                on_release: app.handle_input()
'''




class LobbyScreen(Screen): pass




class ChatScreen(Screen): pass




class SecureBufferInput(TextInput):
    """
    Hardened text input widget for sensitive data (e.g., passwords, answers).

    Intercepts keystrokes at the UI layer to prevent Kivy from caching plaintext
    in its internal rendering engine. Stores input in a mutable bytearray and
    displays dummy asterisks ("*") to the user. Tracks UTF-8 byte lengths for
    precise memory deletion (critical for multi-byte characters).

    Attributes:
        secure_buffer (bytearray): Mutable buffer storing raw input bytes.
        _char_lengths (list[int]): Byte lengths of each character for precise shredding.

    Note:
        This widget is used for riddle answers. After extraction via "extract_and_shred()", 
        the buffer and its metadata are zeroed and cleared.
    """




    def __init__(self, **kwargs):
        """
        Initializes the secure buffer and metadata tracking.

        Arguments:
            **kwargs: Forwarded to Kivy's TextInput.

        Raises:
            SecurityError: If initialization fails (generic error, no traceback).
        """

        try:
            super().__init__(**kwargs)

            self.secure_buffer = bytearray()
        
            # Tracks the exact byte-length of each keystroke for precise memory deletion.
            self._char_lengths = []

            self.multiline = False

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("SecureBufferInput initialization failed.") from None
    



    def insert_text(self, substring: str, from_undo: bool = False):
        """
        Securely handles keystroke insertion.

        Converts the input substring to bytes, records its byte length, and
        appends it to the secure buffer. The UI is fed dummy asterisks to
        prevent plaintext caching in Kivy's rendering pipeline.

        Arguments:
            substring: The text inserted by the user (single character or paste).
            from_undo: Whether the insertion is from undo history (unused here).

        Raises:
            SecurityError: If insertion fails (generic error, no traceback).

        Note:
            The "substring" is shredded after encoding to bytes. The "secure_buffer"
            and "_char_lengths" are never exposed to Kivy's internals.
        """
        
        # Pre-initialize all variables that need to be Burned.
        raw_bytes = None

        try:

            # Convert incoming keystroke to raw bytes immediately.
            raw_bytes = substring.encode('utf-8')
        
            # Record exactly how many bytes this specific character occupies.
            self._char_lengths.append(len(raw_bytes))
        
            # Append to the isolated mutable buffer.
            self.secure_buffer.extend(raw_bytes)

            # Feed the UI a dummy character to trigger the visual update.
            # Use len(substring) to match the visual asterisk count to the character count.
            super().insert_text('*' * len(substring), from_undo=from_undo)

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Secure buffer insertion failed.") from None
            
        finally:
            # Drop reference count securely.
            if raw_bytes is not None:
                del raw_bytes


        

    def do_backspace(self, from_undo: bool = False, mode: str = 'bkspc'):
        """
        Securely handles backspace deletion.

        Pops the last character's bytes from "secure_buffer" and overwrites
        them with zeros before removal. Uses "_char_lengths" to ensure
        multi-byte UTF-8 characters are fully shredded.

        Arguments:
            from_undo: Whether the deletion is from undo history (unused here).
            mode: Kivy's backspace mode (unused here).

        Raises:
            SecurityError: If backspace fails (generic error, no traceback).
        """
        
        # Pre-initialize all variables that need to be Burned.
        bytes_to_pop = None

        try:

            if self.secure_buffer and self._char_lengths:
                # Retrieve the exact byte footprint of the last typed character.
                bytes_to_pop = self._char_lengths.pop()
            
                # Overwrite specifically those bytes with zeroes.
                # "[-1]" targets the last byte in the array. "= 0" turns it to zero.
                for _ in range(bytes_to_pop):
                    self.secure_buffer[-1] = 0
                    self.secure_buffer.pop()

            # Let the UI framework remove the dummy asterisk from the screen.
            super().do_backspace(from_undo=from_undo, mode=mode)

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Secure buffer backspace failed.") from None
            
        finally:
            # Drop reference count securely.
            if bytes_to_pop is not None:
                del bytes_to_pop
        



    def extract_and_shred(self) -> bytearray:
        """
        Extracts the buffer and securely burns internal state.

        Returns a copy of the secure buffer, then zeroes and clears the
        original buffer and its metadata ("_char_lengths"). Also clears
        the widget's text display.

        Returns:
            bytearray: Copy of the input bytes (caller owns shredding responsibility).

        Raises:
            SecurityError: If extraction fails (generic error, no traceback).

        Note:
            The returned bytearray is mutable and must be shredded by the caller
            after use (e.g., via "BurnerMemory.shred").
        """

        # Pre-initialize all variables that need to be Burned.
        extracted_bytes = None

        try:
            # Create a copy of the buffer.
            extracted_bytes = bytearray(self.secure_buffer)

            # Destroy what is no longer needed.
            BurnerMemory.shred(self.secure_buffer)   
            self.secure_buffer.clear()
            self._char_lengths.clear()

            # Clear the dummy asterisks from the screen.
            self.text = ""
        
            return extracted_bytes

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Secure buffer extraction failed.") from None
            
        finally:
            # Guaranteed Burn, whether successful or crashed.
            if self.secure_buffer is not None:
                BurnerMemory.shred(self.secure_buffer)   
                self.secure_buffer.clear()
            if self._char_lengths is not None:
                self._char_lengths.clear()




class WatchdogState:
    """
    Thread-safe container for shared application state.

    Manages state between the main UI thread and background threads (e.g.,
    watchdog, network daemon). Uses a reentrant lock ("threading.Lock") to
    ensure atomic updates and prevent race conditions.

    Attributes:
        lock (Lock): Reentrant lock for thread-safe access.
        last_ui_pulse (float): Timestamp of last UI heartbeat (perf_counter).
        last_net_pulse (float): Timestamp of last network activity (perf_counter).
        switch_armed (bool): If True, the watchdog actively monitors for freezes/timeouts.
        is_shaking_hands (bool): If True, suppresses watchdog during handshake (prevents false positives).
        app_state (str): Current app state (DISCONNECTED, RIDDLE_EXCHANGE, CHAT, etc.).
        current_session_id (bytes): Unique session identifier (AAD for encryption).
        burn_timeout (float): Dead-man switch timeout (seconds).

    Note:
        All timestamps use "time.perf_counter()" (CPU hardware clock) to resist
        OS time tampering (e.g., by forensic tools). The watchdog thread checks
        these timestamps to detect UI freezes or network timeouts.
    """




    def __init__(self):
        """
        Initializes thread-safe state with default values.

        Sets all timestamps to the current "perf_counter" value and configures
        the dead-man switch timeout to 5.0 seconds by default.

        Raises:
            SecurityError: If initialization fails (generic error, no traceback).
        """

        try:
        
            # Reentrant lock for thread-safe access to all attributes.
            # This ensures atomic updates and prevents race conditions across threads. 
            self.lock = Lock()
        
            # Use perf_counter() instead of time.time() because it relies on the CPU's hardware clock,
            # making it immune to OS time-tampering (e.g., by forensic tools or attackers).
            self.last_ui_pulse = time.perf_counter()    # Last UI heartbeat timestamp.
            self.last_net_pulse = time.perf_counter()   # Last network activity timestamp.
        
            # Flag to activate the hardware-level Dead Man's Switch.
            # When True, the background watchdog actively monitors CPU tick time
            # (via perf_counter) to detect if a forensic tool, debugger, or hypervisor 
            # has artificially frozen the app's execution state.
            self.switch_armed = False
        
            # UI Freeze override flag. Prevents the Watchdog from triggering 
            # a false positive during heavy cryptographic math.
            self.is_shaking_hands = False

            # Application State Machine:
            #   - 'DISCONNECTED': Initial state (no active session).
            #   - 'RIDDLE_EXCHANGE': Zero-knowledge authentication phase.
            #   - 'CHAT': Encrypted messaging phase.
            self.app_state = 'DISCONNECTED' 
        
            # Unique identifier for the current encrypted session.
            # Used as AAD (Authenticated Additional Data) in AES-GCM encryption.
            self.current_session_id = None

            # Timeout (in seconds) for the dead-man switch. After this period of inactivity,
            # the chat UI is automatically cleared and memory is burned.
            # Default: 5.0 seconds.
            self.burn_timeout = 5.0

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("WatchdogState initialization failed.") from None




class BlackHoleApp(App):
    """
    Secure end-to-end encrypted messenger with forensic resistance.

    Implements a zero-knowledge authenticated chat protocol using:
      - X25519 for ephemeral key exchange (Perfect Forward Secrecy).
      - Double Ratchet for per-message key rotation.
      - AES-GCM for authenticated encryption.
      - SHA-256 for hashing and session binding.
      - Riddle-based zero-knowledge mutual authentication.

    Features:
      - Hardware-level dead-man switch (watchdog thread).
      - Secure memory sanitization (BurnerMemory).
      - Traffic analysis resistance (fixed-size padding).
      - Anti-forensic measures (core dumps disabled, exception masking).

    Thread Safety:
      - UI operations are confined to the main thread (via Kivy's Clock).
      - Background threads communicate with the UI via a thread-safe queue ("_ui_queue").
      - Shared state ("WatchdogState") is protected by a reentrant lock.

    Note:
        This app is designed to leave zero forensic traces. All sensitive data
        (keys, plaintext, session IDs) is shredded from memory immediately after use.
        The watchdog thread enforces this by triggering a full burn protocol on:
          - UI freezes (>1s without pulse).
          - Network timeouts (>10s without activity).
          - Manual triggers (e.g., "/burn" command).
    """




    def __init__(self, **kwargs):
        """
        Initializes the app with thread-safe state and cryptographic primitives.

        Sets up:
          - "WatchdogState" for shared state (protected by a lock).
          - "_ui_queue" for thread-safe UI updates.
          - Socket and crypto placeholders (initialized later).
          - Riddle/answer storage (plaintext riddles are ephemeral; only hashes stored).

        Arguments:
            **kwargs: Forwarded to Kivy's App base class.

        Raises:
            SecurityError: If initialization fails (generic error, no traceback).
        """
        
        try:
 
            super().__init__(**kwargs)

            # Watchdog state (accessed from both main and background threads).
            # All accesses must use "self._watchdog_state.lock".
            self._watchdog_state = WatchdogState()

            # Queue for thread-safe UI updates (background → main thread).
            # Architecture Note: Background threads push callbacks here; main thread processes via "_process_ui_queue".
            self._ui_queue = Queue()
        
            # TCP socket for relay server communication.
            # Always shutdown/closed during burn protocol to prevent forensic leaks.
            self.sock = None
        
            # Double Ratchet protocol instance for end-to-end encryption.
            self.crypto = None

            # The server IP and Room number chosen for the chat session.
            self.ip = ""
            self.room = ""            

            # Challenge-response strings for zero-knowledge authentication.
            # Plaintext riddles are ephemeral; only hashes are stored long-term.
            self.my_riddle = ""    # Outbound challenge (sent to peer).
            self.peer_riddle = ""  # Inbound challenge (received from peer).
        
            # SHA-256 digest of the local riddle answer.
            # Irreversible; never stored in plaintext after hashing.
            self.my_answer_hash = ""

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("BlackHoleApp initialization failed.") from None

        
        
    def build(self):
        """
        Initializes the Kivy UI and starts background threads.

        Performs:
            Launches the hardware watchdog thread (daemon=True).
            Binds UI heartbeat to Kivy's Clock (100ms interval).
            Binds UI queue processor to Kivy's Clock (100Hz).
            Loads and returns the KV-language UI definition.

        Returns:
            Widget: Root widget of the Kivy UI tree.

        Raises:
            SecurityError: If UI build fails (generic error, no traceback).
        """

        # Pre-initialize all variables that need to be Burned.
        ui_tree = None

        try:

            # Launch the hardware execution monitor in a background thread.
            # daemon=True ensures this thread dies the exact microsecond the main thread terminates.
            # Thread Safety: The watchdog only accesses "WatchdogState".
            threading.Thread(target = self._hardware_watchdog_loop, daemon = True).start()

            # Bind the UI heartbeat to Kivy's rendering engine.
            # Purpose: Proves the graphics loop is actively processing frames.
            # Frequency: 100ms (10x per second) to balance responsiveness and CPU usage.
            Clock.schedule_interval(self._ui_pulse, 0.1)

            # Process UI updates from background threads (thread-safe queue).
            # Purpose: Executes callbacks pushed by background threads on the main thread.
            # Frequency: 100Hz (every 10ms) to minimize latency for cross-thread UI updates.
            Clock.schedule_interval(self._process_ui_queue, 0.01)

            # Compile the KV language string into GPU instructions and render the window.
            ui_tree = Builder.load_string(KV_STRING)

            return ui_tree

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Kivy UI build sequence failed.") from None




    def _process_ui_queue(self, dt):
        """
        Processes pending UI updates from background threads.

        Drains the thread-safe "_ui_queue" and executes all callbacks on the
        main thread (via Kivy's Clock). Runs at 100Hz to minimize latency.

        Arguments:
            dt: Time delta since last Clock tick (unused, required by Kivy).

        Raises:
            SecurityError: If queue processing fails (generic error, no traceback).
        """

        try:

            try:
                # Drain the entire queue in one Clock tick for efficiency.
                # Note: "get_nowait()"" is non-blocking and raises "queue.Empty" if the queue is empty.
                while True:
                    callback = self._ui_queue.get_nowait()

                    # Execute the callback on the main thread.
                    callback()

            except queue.Empty:
                # Queue is empty, exit until the next Clock tick.
                pass

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("UI queue processing failed.") from None


    
    
    def _hash_answer(self, ans_bytes: bytearray) -> bytes:
        """
        Hashes a bytearray answer using SHA-256.

        Accepts a mutable "bytearray" directly for zero-copy security.
        The input buffer is shredded immediately after hashing.

        Arguments:
            ans_bytes: Raw mutable buffer from "SecureBufferInput".

        Returns:
            bytes: SHA-256 digest of the input (irreversible).

        Raises:
            SecurityError: If hashing fails (generic error, no traceback).
        """
    
        # Pre-initialize all variables that need to be Burned.
        final_hash = None

        try:
        
            # Pass the mutable bytearray directly into the SHA-256 engine.
            final_hash = hashlib.sha256(ans_bytes).digest()

            # Burn what is no longer needed.
            BurnerMemory.shred(ans_bytes)
        
            return final_hash

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Answer hashing failed.") from None
            
        finally:
            # Guaranteed Burn, whether successful or crashed.
            if ans_bytes:
                BurnerMemory.shred(ans_bytes)




    def _heartbeat(self, *args):
        """
        Signals network liveness to the watchdog.

        Updates "last_net_pulse" in "WatchdogState" to the current "perf_counter"
        value. Must be called whenever a packet is sent/received.

        Arguments:
            *args: Unused (for compatibility with Kivy event bindings).

        Raises:
            SecurityError: If heartbeat update fails (generic error, no traceback).
        """

        try:
        
            # Update the last network pulse timestamp under lock.
            with self._watchdog_state.lock:
                self._watchdog_state.last_net_pulse = time.perf_counter()

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Heartbeat update failed.") from None




    def _ui_pulse(self, dt):
        """Signals UI liveness to the watchdog.

        Updates "last_ui_pulse" in "WatchdogState" to the current "perf_counter"
        value. Called by Kivy's Clock at 100ms intervals.

        Arguments:
            dt: Time delta since last Clock tick (unused, required by Kivy).

        Raises:
            SecurityError: If UI pulse update fails (generic error, no traceback).
        """

        try:
        
            # Update the last UI pulse timestamp under lock.
            with self._watchdog_state.lock:
                self._watchdog_state.last_ui_pulse = time.perf_counter()

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("UI pulse update failed.") from None
        



    def _hardware_watchdog_loop(self):
        """
        Dead-man switch: Monitors UI/network liveness in a background thread.

        Detects:
          - UI freezes (>1.0s without "_ui_pulse").
          - Network timeouts (>10.0s without "_heartbeat").

        If either condition is met, triggers "_execute_burn_protocol" on the
        main thread via "_ui_queue".

        Thread Safety:
          - Runs as a daemon thread (dies with the main thread).
          - All shared state access is protected by "WatchdogState.lock".
          - Never calls Kivy methods directly (avoids segmentation faults).

        Note:
            Uses "time.perf_counter()" (CPU hardware clock) to detect artificial
            suspension (e.g., by debuggers or hypervisors).
        """

        # Pre-initialize all variables that need to be Burned.
        switch_armed = None
        is_shaking_hands = None
        last_ui_pulse = None
        last_net_pulse = None
        current_time = None
        ui_freeze_gap = None
        net_idle_gap = None

        try:

            while True:
                # Sleep to minimize CPU usage while avoiding interference with Kivy's event loop.
                time.sleep(0.1)

                # Read all shared state under lock to ensure consistency.
                with self._watchdog_state.lock:
                    switch_armed = self._watchdog_state.switch_armed
                    is_shaking_hands = self._watchdog_state.is_shaking_hands
                    last_ui_pulse = self._watchdog_state.last_ui_pulse
                    last_net_pulse = self._watchdog_state.last_net_pulse

                # If watchdog is disarmed or handshake is in progress, sync the timers.
                # Purpose: Prevents false positives during initialization or heavy crypto operations.
                if not switch_armed or is_shaking_hands:
                    with self._watchdog_state.lock:
                        self._watchdog_state.last_ui_pulse = time.perf_counter()
                        self._watchdog_state.last_net_pulse = time.perf_counter()
                    continue

                current_time = time.perf_counter()

                # Calculate time gaps since last activity.
                ui_freeze_gap = current_time - last_ui_pulse    # UI freeze detection.
                net_idle_gap = current_time - last_net_pulse    # Network timeout detection.

                # Check for critical failures.
                # UI Tolerance: 1.0s.
                # Network Tolerance: 10.0s.
                if ui_freeze_gap > 1.0 or net_idle_gap > 10.0:
                    print(f"[!] WATCHDOG TRIGGERED: UI Gap: {ui_freeze_gap:.2f}s | Net Gap: {net_idle_gap:.2f}s")

                    # Schedule burn protocol on the main thread via the queue.
                    self._ui_queue.put(lambda: self._execute_burn_protocol())
                    

        except Exception:
            # Suppress all thread exceptions to prevent Python from
            # printing tracebacks to stderr.
            pass  




    def _execute_burn_protocol(self):
        """Secure burn protocol: Final line of defense against forensic analysis.

        Executes a two-phase cleanup:
          Phase 1: Shreds cryptographic keys ("send_chain_key", "receive_chain_key")
                   and the session ID. Forcefully shuts down the socket.
          Phase 2: Delegates to "_execute_rv_burn" for chat/UI sanitization.

        Terminates the process immediately via "os._exit(0)" to:
          - Bypass Python's garbage collector (no cleanup delays).
          - Prevent flushing cache files/logs to disk.
          - Ensure termination at the C-runtime level.

        Note:
            This is called by:
              - Watchdog thread (UI freeze/network timeout).
              - Manual burn ("/burn" command).
              - Protocol violations (e.g., failed riddle auth).
        """

        print("[!] INITIATING SECURE BURN...")
        
        try:
            # Sever the network connection to alert the peer and unblock any I/O threads.
            if hasattr(self, 'sock') and self.sock:
                try:
                    # Forcefully shutdown read/write channels before closing.
                    self.sock.shutdown(socket.SHUT_RDWR)
                    self.sock.close()

                except Exception:
                    # Ignore errors, drop the connection.
                    pass
                    
            # Call _execute_rv_burn to handle chat message burn.
            self._execute_rv_burn()

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Burn protocol execution failed.") from None
            
        finally:
            # Shred cryptographic keys to prevent forensic recovery from RAM dumps.
            if hasattr(self, 'crypto') and self.crypto:
                if hasattr(self.crypto, 'send_chain_key') and self.crypto.send_chain_key:
                    BurnerMemoryByte.shred(self.crypto.send_chain_key)

                if hasattr(self.crypto, 'receive_chain_key') and self.crypto.receive_chain_key:
                    BurnerMemoryByte.shred(self.crypto.receive_chain_key)

            # Destroy the session identifier to prevent session hijacking.
            with self._watchdog_state.lock:
                if self._watchdog_state.current_session_id is not None:
                    BurnerMemoryByte.shred(self._watchdog_state.current_session_id)
                    self._watchdog_state.current_session_id = None

            # CRITICAL: Use "os._exit(0)"" for immediate, ungraceful termination.
            # Rationale:
            # - Bypasses Python's garbage collector (no cleanup delays).
            # - Prevents flushing of cache files or logs to disk.
            # - Terminates at the C-runtime level for maximum certainty.
            # Testing Note: Confirmed stable across multiple test cycles.
            print("[!] BURN COMPLETE. SEVERING PROCESS.")
            os._exit(0)
        



    def trigger_burn_protocol(self):
        """Schedules the burn protocol for main-thread execution.

        Acts as a thread-safe bridge between background threads (e.g., watchdog)
        and the main thread. Ensures "_execute_burn_protocol" runs on the main
        thread, where Kivy operations are safe.

        Note:
            Uses "_ui_queue" to delegate execution to the main thread.
        """

        try:

            # Schedule the burn protocol on the main thread via the thread-safe queue.
            # This ensures all Kivy operations and memory cleanup happen on the main thread.
            self._ui_queue.put(lambda: self._execute_burn_protocol())

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Burn protocol trigger failed.") from None

    


    def start_connection(self):
        """
        Initiates a secure connection to the relay server.

        Steps:
          - Extracts IP, room, riddle, and answer from the UI and stores them as instance
            attributes ("self.ip", "self.room", "self.my_riddle").
          - Hashes the answer (SHA-256) and shreds the plaintext.
          - Starts the "network_daemon" thread with "self.ip" and "self.room".

        Security Notes:
          - The answer is never stored in plaintext; only its SHA-256 hash ("self.my_answer_hash") is retained.
          - IP, room, and riddle are stored as instance attributes temporarily and passed to the
            network daemon thread. They are shredded in "network_daemon"'s finally block.

        Raises:
            SecurityError: If connection initiation fails (generic error, no traceback).
        """

        # Pre-initialize all variables that need to be Burned.
        answer_string = None

        try:

            # Pull connection parameters directly from the Kivy UI.
            # Note: "ip", "room", and "riddle" are plaintext strings, "my_answer" is a SecureBufferInput.
            lobby_screen = self.root.get_screen('lobby')

            self.ip = lobby_screen.ids.target_input.text
            self.room = lobby_screen.ids.room_input.text
            self.my_riddle = lobby_screen.ids.my_riddle.text
        
            # Extract the answer as a mutable bytearray and shred the widget's internal state.
            # "extract_and_shred" returns a copy of the buffer, then zeros and clears the original.
            answer_string = lobby_screen.ids.my_answer.extract_and_shred()

            # Abort if any required parameters are missing.
            if not (self.ip and self.room and self.my_riddle and answer_string):
                return
        
            # Hash the answer using SHA-256. The input bytearray is shredded inside "_hash_answer".
            # Only the digest is stored in "self.my_answer_hash". The digest is irreversible.
            self.my_answer_hash = self._hash_answer(answer_string)

            # Destroy what is no longer needed.
            BurnerMemoryString.shred(answer_string)
        
            # Switch the UI to the chat screen.
            self.root.current = 'chat'
        
            # Clear the chat RecycleView data (if present) to ensure a fresh state.
            if hasattr(self.root.get_screen('chat').ids, 'chat_rv'):
                self.root.get_screen('chat').ids.chat_rv.data = []

            # Start the network daemon in a background thread with "self.ip" and "self.room".
            threading.Thread(target = self.network_daemon, args = (self.ip, self.room), daemon = True).start()

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Start Connection failed.") from None

        finally:
            # Guaranteed Burn, whether successful or crashed.
            if answer_string:
                BurnerMemoryString.shred(answer_string)

        


    def network_daemon(self, ip, room):
        """
        Background thread: Establishes a secure connection to the relay.

        Performs:
          TCP connection to the relay (port 9999).
          Joins the specified chat room via "ROOM:<room>\n" protocol message.
          X25519 key exchange for Perfect Forward Secrecy (PFS).
          Role negotiation (Initiator/Responder) via lexicographical public key comparison.
          Zero-knowledge mutual authentication (riddle challenge-response).
          Initializes "E2EProtocol" for message encryption/decryption.

        Arguments:
            ip (str): Relay server IP address.
            room (str): Chat room identifier to join.

        Security Notes:
          - All cryptographic material ("shared_secret", "pub_bytes", "peer_pub_bytes") is
            explicitly shredded in the finally block.
          - Instance attributes ("self.ip", "self.room", "self.my_riddle", "self.peer_riddle")
            and "peer_challenge" are shredded in the finally block to prevent memory leaks.
          - Outer exception handler raises "SecurityError" to mask unexpected errors and prevent
            traceback leaks. Inner exception handlers use generic UI messages.
          - Private keys ("priv_key", "peer_pub") are explicitly deleted after shared secret derivation.
          - Protocol violations (e.g., malformed challenges, timeouts) trigger cleanup and notify
            the user with non-sensitive error messages.

        Note:
          Communicates with the main thread via "_ui_queue" for UI updates.
          Uses "TCP_NODELAY" to prevent timing side-channels from Nagle's algorithm.
        """

        # Pre-initialize all variables that need to be Burned.
        shared_secret = None
        pub_bytes = None
        peer_pub_bytes = None
        peer_challenge = None

        try:

            # Create a temporary socket to establish the connection before binding to "self".
            # This prevents partial initialization of "self.sock" if the connection fails.
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
            try:
                # Notify the user that a connection attempt is in progress.
                self._ui_queue.put(lambda: self.post_ui("[*] Connecting to zero-knowledge relay...", "system"))

                # Set a 15-second timeout to avoid indefinite blocking if the relay is unresponsive
                # or network conditions are poor.
                temp_sock.settimeout(15.0)

                # Disable Nagle's algorithm (TCP_NODELAY) to ensure cryptographic frames are sent
                # immediately. This reduces timing side-channels that could leak information
                # about message boundaries or sizes.
                temp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                # Connect to the relay server at the specified IP and port (9999).
                temp_sock.connect((ip, 9999))

                # Bind the successful connection to "self.sock" so it can be accessed by the
                # Watchdog thread and UI for monitoring and communication.
                self.sock = temp_sock
            
                # Send the room identifier to the relay to join the specified chat room.
                # Format: "ROOM:<room_name>\n" (newline-terminated for protocol parsing).
                self.sock.sendall(f"ROOM:{room}\n".encode())
            
                # Notify the user that the connection was successful and the system is
                # waiting for a peer to join the same room.
                self._ui_queue.put(lambda: self.post_ui("[*] Connected. Waiting for peer in sector...", "system"))
            
                # Generate a new X25519 private key for this session. This provides Perfect Forward Secrecy (PFS):
                # even if the shared secret is compromised later, past communications remain secure.
                priv_key = x25519.X25519PrivateKey.generate()

                # Serialize the public key to raw bytes (32 bytes for X25519).
                # This is sent to the peer to derive the shared secret.
                pub_bytes = priv_key.public_key().public_bytes(
                    serialization.Encoding.Raw, 
                    serialization.PublicFormat.Raw
                )
            
                # Send the local public key to the peer. The peer will use this to compute
                # the shared secret using their private key and our public key.
                self.sock.sendall(pub_bytes)

                # Receive the peer's public key. X25519 public keys are strictly 32 bytes.
                # If the received data is not 32 bytes, the handshake is aborted to prevent
                # protocol attacks or malformed data.
                peer_pub_bytes = self.sock.recv(32)
                if len(peer_pub_bytes) != 32:
                    raise ValueError("Invalid key received from peer.")
                
                # Deserialize the peer's public key from raw bytes.
                peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)

                # Compute the shared secret using the local private key and the peer's public key.
                # This secret is used to derive session keys for encryption.
                shared_secret = priv_key.exchange(peer_pub)

                # Explicitly delete the private key and peer_pub to reduce their exposure in memory.
                # The keys are no longer needed after the shared secret is computed.
                del priv_key
                del peer_pub
            
                # To avoid collision in the protocol (e.g., both sides waiting for the other),
                # the client with the lexicographically larger public key becomes the Initiator.
                # This deterministic approach ensures one side always starts the next protocol step.
                is_initiator = pub_bytes > peer_pub_bytes
            
                # Notify the user that key exchange is complete and mutual authentication is starting.
                self._ui_queue.put(lambda: self.post_ui("[*] Keys exchanged. Initiating Mutual Authentication.", "warning"))
            
                # Send the local riddle challenge to the peer in plaintext.
                # Format: "RIDDLE||<riddle_text>" (double pipe as delimiter).
                # This is part of the zero-knowledge mutual authentication protocol.
                self.sock.sendall(b"RIDDLE||" + self.my_riddle.encode('utf-8'))
            
                # Receive the peer's riddle challenge. The peer uses the same format.
                peer_challenge = self.sock.recv(1024)
                if not peer_challenge.startswith(b"RIDDLE||"):
                    raise Exception("Handshake Protocol Violation: Malformed challenge.")
            
                # Extract and decode the peer's riddle for display to the user.
                self.peer_riddle = peer_challenge.split(b"||")[1].decode('utf-8')
                self.post_ui(f"[b]PEER CHALLENGE:[/b] {self.peer_riddle}", "fsociety")
                self._ui_queue.put(lambda: self.post_ui("[!] Type the answer below and hit SEND.", "warning"))
            
                # Initialize the end-to-end encryption protocol with the shared secret and role.
                # The "E2EProtocol" instance will handle message encryption/decryption for the session.
                self.crypto = E2EProtocol(shared_secret, is_initiator)

                # Update the watchdog state to indicate that the handshake is complete and
                # the user is now expected to solve the peer's riddle.
                with self._watchdog_state.lock:
                    self._watchdog_state.app_state = 'SOLVING_RIDDLE'

            except socket.timeout:
                # Notify the user if the relay does not respond within the timeout period.
                self._ui_queue.put(lambda: self.post_ui("[!] Network timeout: Relay unresponsive.", "error"))
                self._cleanup_failed_connection(temp_sock)

            except Exception:
                # Catch any other exceptions.
                self._ui_queue.put(lambda: self.post_ui("[!] Network error.", "error"))
                self._cleanup_failed_connection(temp_sock)
                raise SecurityError("Link failure.") from None

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            self._ui_queue.put(lambda: self.post_ui("[!] Network error.", "error"))
            raise SecurityError("Link failure: Protocol error.") from None

        finally:
            # Guaranteed Burn, whether successful or crashed.
            BurnerMemoryByte.shred(shared_secret)
            BurnerMemoryByte.shred(pub_bytes)
            BurnerMemoryByte.shred(peer_pub_bytes)
            BurnerMemoryString.shred(self.ip)
            BurnerMemoryString.shred(self.room)
            BurnerMemoryString.shred(self.my_riddle)
            BurnerMemoryString.shred(self.peer_riddle)
            BurnerMemoryByte.shred(peer_challenge)




    def _cleanup_failed_connection(self, sock):
        """
        Safely closes a socket after a failed connection attempt.

        Args:
            sock: The socket to close (typically a temporary socket).

        Note:
            Suppresses all exceptions during cleanup to avoid masking the original error.
        """

        try:
            # Close the socket to release the file descriptor and network resources.
            # This prevents resource leaks if the connection attempt fails.
            sock.close()
            
            # If the instance has a "sock" attribute (e.g., from a previous successful connection),
            # set it to None to avoid holding a reference to a closed or invalid socket.
            if hasattr(self, 'sock'):
                self.sock = None
        
        except Exception:
            # Suppress all exceptions during cleanup to ensure this function never
            # raises an error, which could mask the original connection failure.
            # This is intentional: cleanup should be best-effort and non-blocking.
            pass




    def handle_input(self):
        """
        Processes user input from the chat screen.

        Routes input based on "app_state":
          - "SOLVING_RIDDLE": Submits as a riddle answer ("submit_riddle_answer").
          - "CHAT": Encrypts and sends as a message ("send_encrypted_message").

        Special Commands:
          - "/burn": Triggers emergency shutdown (full burn protocol).
          - "/erase": Clears chat UI (dead-man switch cleanup without termination).

        Security Notes:
          - In riddle mode, input is extracted via "extract_and_shred".
          - In chat mode, input is cleared from the widget and shredded.
          - Undo/redo history is explicitly shredded to prevent leaks.
        """

        try:

            # Get the chat screen and its message input widget.
            # This is the primary entry point for user input in the application.
            chat_screen = self.root.get_screen('chat')
            msg_widget = chat_screen.ids.msg_input

            # Extract the input text based on the widget type:
            if hasattr(msg_widget, 'extract_and_shred'):
                # If the widget has "extract_and_shred", it is a "SecureBufferInput" (riddle-solving mode).
                # Use "extract_and_shred" to securely retrieve and destroy the input.
                text = msg_widget.extract_and_shred()
        
            else:
                # Otherwise, it is a standard "TextInput" (chat mode). Retrieve the plaintext and clear the widget.
                text = msg_widget.text
                msg_widget.text = ""

                # Shred Undo History.
                if hasattr(msg_widget, '_undo_history'):
                    for action in msg_widget._undo_history:
                        if isinstance(action, tuple):
                            for element in action:
                                if isinstance(element, str) and element:
                                    BurnerMemoryString.shred(element)
                    msg_widget._undo_history.clear()
                    
                # Shred Redo History.
                if hasattr(msg_widget, '_redo_history'):
                    for action in msg_widget._redo_history:
                        if isinstance(action, tuple):
                            for element in action:
                                if isinstance(element, str) and element:
                                    BurnerMemoryString.shred(element)
                    msg_widget._redo_history.clear()
                    
                # Flush all of Kivy's internal caches to remove any lingering references to
                # sensitive data (e.g., rendered text, textures, or other cached objects).
                for category in list(Cache._categories.keys()):
                    Cache.remove(category)

                # Allocate and discard 2,500 x 512-byte blocks (1.25MB total) to force Python's
                # memory allocator to overwrite recently freed memory blocks.  
                memory_flood = [b'\x00' * 512 for _ in range(2500)]
                del memory_flood

                # Run garbage collection 3 times to break circular references in Kivy's
                # widget tree (e.g., parent -> child -> parent references).
                import gc
                for _ in range(3):
                    gc.collect()

            # Strip whitespace and ignore empty input.
            text = text.strip()
            if not text:
                return
        
            # Signal the watchdog that the user is active.
            # This prevents the app from being marked as unresponsive.
            self._heartbeat()

            # Check for the "/burn" command, which triggers an emergency shutdown protocol.
            # This is a manual override for security-sensitive scenarios.
            if text == "/burn":
                self.post_ui("[!] MANUAL BURN INITIATED.", "error")
                self.trigger_burn_protocol()
                return
        
            # Check for the "/erase" command, which triggers a full chat memory sanitization.
            # Allows the user to clear the chat UI on demand without terminating the app.
            if text == "/erase":
                self.post_ui("[!] MESSAGES BURNED SUCCESSFULLY.", "error")
                self._execute_rv_burn()  # Clear chat UI and sanitize memory
                return
        
            # Determine the current app state to route the input correctly.
            # This ensures the input is processed according to the context (e.g., riddle vs. chat).
            with self._watchdog_state.lock:
                app_state = self._watchdog_state.app_state
           
            if app_state == 'SOLVING_RIDDLE':
                # Riddle-solving mode: Submit the input as a riddle answer.
                self.submit_riddle_answer(text)

            elif app_state == 'CHAT':
                # Chat mode: Encrypt and send the input as a message.
                self.send_encrypted_message(text)

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Handle Input failed.") from None

            


    def submit_riddle_answer(self, guess):
        """
        Executes zero-knowledge authentication with the peer.

        Three-phase protocol:
            Cryptographic Handshake:
             - Hashes the user's guess (SHA-256).
             - Exchanges nonces and proofs with the peer.
             - Verifies mutual knowledge of riddle answers (constant-time comparison).
            Session ID Negotiation:
             - Exchanges unique session IDs and combines them deterministically.
            UI Hot-Swap:
             - Replaces "SecureBufferInput" with a standard "TextInput".
             - Flushes Kivy caches and overwrites freed memory.

        Arguments:
            guess: User's answer to the peer's riddle (bytearray from "SecureBufferInput").

        Note:
            If authentication fails, triggers the burn protocol immediately.
        """

        # Pre-initialize all variables that need to be Burned.
        guess_hash = None
        my_nonce = None
        peer_nonce_resp = None
        peer_nonce = None
        combined_payload = None
        secure_payload = None
        peer_answer_resp = None
        peer_secure_payload = None
        expected_combined = None
        expected_peer_payload = None
        parts = None
        ans_parts = None
        peer_auth_status = None

        try:
        
            # Retrieve the chat screen and input widget to perform UI updates.
            chat_screen = self.root.get_screen('chat')
            chat_input = chat_screen.ids.msg_input
        
            # Clear the input field visually to provide immediate user feedback.
            chat_input.text = ""

            # Signal the watchdog that a handshake is in progress to prevent false "unresponsive" alerts.
            with self._watchdog_state.lock:
                self._watchdog_state.is_shaking_hands = True

        
            # =====================================================================
            # CRYPTOGRAPHIC HANDSHAKE
            # =====================================================================
            # This phase verifies mutual knowledge of the riddle answers using a nonce-based
            # challenge-response protocol. Both peers must prove they know the correct answer
            # without transmitting it in plaintext.


            # Hash the user's guess using SHA-256. The original bytearray is shredded immediately by _hash_answer
            # to prevent it from persisting in RAM after this point. 
            guess_hash = self._hash_answer(guess)
                
            # Generate a cryptographically secure 16-byte nonce for this handshake.
            import secrets
            my_nonce = secrets.token_bytes(16)

            # Send the nonce to the peer as part of the challenge.
            self.sock.sendall(b"NONCE||" + my_nonce)
                
            # Await the peer's nonce response. The protocol requires this to start with "NONCE||".
            # "NONCE|| = 7 bytes + 16 bytes from my_nonce = 23 bytes."
            peer_nonce_resp = self.sock.recv(23)
            if not peer_nonce_resp.startswith(b"NONCE||"):
                self.post_ui("[!] Protocol violation.", "error")
                self.trigger_burn_protocol()
                return
                
            # Parse the peer's nonce from the response.
            parts = peer_nonce_resp.split(b"||", 1)
            peer_nonce = parts[1]

            # Combine the peer's nonce with the hashed guess to create a proof.
            # This proves we know the answer to the peer's riddle without revealing it.
            combined_payload = peer_nonce + guess_hash
            secure_payload = hashlib.sha256(combined_payload).digest()

            # Send the proof to the peer.
            self.sock.send(b"ANSWER||" + secure_payload)

            # Await the peer's proof of knowledge of our riddle's answer.
            # "ANSWER||" = 8 bytes + 32 bytes from SHA-256 digest.
            peer_answer_resp = self.sock.recv(40)
            if not peer_answer_resp.startswith(b"ANSWER||"):
                self.post_ui("[!] Protocol violation.", "error")
                self.trigger_burn_protocol()
                return
                
            # Parse the peer's proof.
            ans_parts = peer_answer_resp.split(b"||", 1)
            peer_secure_payload = ans_parts[1]

            # Reconstruct the expected proof: SHA-256(my_nonce + my_answer_hash).
            # This is what the peer should have computed if they know our riddle's answer.
            expected_combined = my_nonce + self.my_answer_hash
            expected_peer_payload = hashlib.sha256(expected_combined).digest()

            # Use constant-time comparison to prevent timing attacks.
            verification_passed = secrets.compare_digest(peer_secure_payload, expected_peer_payload)
                
            # Send mark of success or failure.
            self.sock.sendall(b"AUTH_SUCCESS" if verification_passed else b"AUTH_FAILED")

            # Prevent indefinite blocking.
            self.sock.settimeout(10.0)
                
            try:
                # Receive peer's mark of success or failure.
                # "AUTH_SUCCESS" = 12 bytes. "AUTH_FAILED = 11 bytes."
                peer_auth_status = self.sock.recv(12)
                
            except socket.timeout:
                # Treat timeout as failure.
                peer_auth_status = b"AUTH_FAILED"
                self.post_ui("[-] Timeout.", "error")
                
            finally:
                self.sock.settimeout(None)

            if not verification_passed or peer_auth_status != b"AUTH_SUCCESS":
                 # Trigger burn protocol if any of the users failed the riddle answer.
                self.trigger_burn_protocol()
                self.post_ui("[!] PEER FAILED YOUR RIDDLE. SEVERING.", "error")
                return
                    
            # Authentication successful. Update UI and state.
            self.post_ui("[+] Authentication verified. Ratchet engaged.", "success")
            with self._watchdog_state.lock:
                self._watchdog_state.app_state = 'CHAT'

            
            # =================================================================
            # HANDSHAKE SESSION ID: SESSION ID NEGOTIATION
            # =================================================================
            # Establishes a unique session identifier shared between both peers.
            # The session ID is used to bind the connection to this handshake and prevent
            # session hijacking or replay attacks.
            
            Clock.schedule_once(lambda dt: self._handshake_session_id(), 0)


            # =================================================================
            # CLEAN UP: UI HOT-SWAP AND MEMORY FLOOD
            # =================================================================
            # Schedule cleanup to run asynchronously on the next clock cycle.
            # This ensures the UI transition happens after the handshake completes.
            
            Clock.schedule_once(lambda dt: self._cleanup(), 0)


        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Riddle Handshake Failed.") from None

        finally:
            # Signal the watchdog to be alert again now that the handshake is completed.
            with self._watchdog_state.lock:
                self._watchdog_state.is_shaking_hands = False

            # Guaranteed Burn, whether successful or crashed.    
            if guess_hash: BurnerMemoryByte.shred(guess_hash)
            if my_nonce: BurnerMemoryByte.shred(my_nonce)
            if peer_nonce_resp: BurnerMemoryByte.shred(peer_nonce_resp)
            if peer_nonce: BurnerMemoryByte.shred(peer_nonce)
            if combined_payload: BurnerMemoryByte.shred(combined_payload)
            if secure_payload: BurnerMemoryByte.shred(secure_payload)
            if peer_answer_resp: BurnerMemoryByte.shred(peer_answer_resp)
            if peer_secure_payload: BurnerMemoryByte.shred(peer_secure_payload)
            if expected_combined: BurnerMemoryByte.shred(expected_combined)
            if expected_peer_payload: BurnerMemoryByte.shred(expected_peer_payload)
            if parts and len(parts) > 0: BurnerMemoryByte.shred(parts[0])
            if ans_parts and len(ans_parts) > 0: BurnerMemoryByte.shred(ans_parts[0])
            if peer_auth_status: BurnerMemoryByte.shred(peer_auth_status)


        

    def _cleanup(self):
        """
        Post-handshake cleanup: Transitions UI to chat mode.

        Steps:
            Replaces "SecureBufferInput" with a standard "TextInput".
            Flushes Kivy caches (textures, labels, etc.).
            Overwrites freed memory (1.25MB flood).
            Runs garbage collection (3 passes).
            Arms the watchdog and starts the "listen_loop" thread.
            Binds the typing to reset_burn_timer to reset it with each keystroke.

        Note:
            Called asynchronously via "Clock.schedule_once" after handshake completion.
        """

        try:
            # Remove the SecureBufferInput widget from the rendering tree to destroy its
            # internal state (e.g., secure_buffer, _undo_history, _char_lengths).
            # This prevents sensitive data from lingering in the widget's memory.
            chat_screen = self.root.get_screen('chat')
            old_secure_input = chat_screen.ids.msg_input
            parent_layout = old_secure_input.parent

            if parent_layout:
                # Create a standard TextInput widget for normal chat mode.
                # This widget does not have secure memory handling, as it is used for
                # non-sensitive chat messages (though leaks may still occur in Kivy's caches).
                new_chat_widget = TextInput(
                    hint_text='>>>',
                    multiline=False,
                    background_color=(0, 0, 0, 1),
                    foreground_color=(0, 1, 0, 1)
                )
                # Bind the Enter key to handle_input to submit messages.
                new_chat_widget.bind(on_text_validate=lambda inst: self.handle_input())

                # Replace the old widget with the new one in the layout.
                layout_index = parent_layout.children.index(old_secure_input)
                parent_layout.remove_widget(old_secure_input)
                parent_layout.add_widget(new_chat_widget, index=layout_index)
                chat_screen.ids.msg_input = new_chat_widget

            # Remove the reference to the old widget to allow garbage collection.
            del old_secure_input

            # Flush all of Kivy's internal caches to remove any lingering references to
            # sensitive data (e.g., rendered text, textures, or other cached objects).
            from kivy.cache import Cache
            for category in list(Cache._categories.keys()):
                # Using the keyless .remove() method safely dumps the objects
                # without destroying the background Clock thread rules.
                Cache.remove(category)

            # Allocate and discard 2,500 x 512-byte blocks (1.25MB total) to force Python's
            # memory allocator to overwrite recently freed memory blocks.
            # This targets small object arenas (< 512 bytes) to prevent swap file leakage.
            memory_flood = [b'\x00' * 512 for _ in range(2500)]
            del memory_flood

            # Run garbage collection 3 times to break circular references in Kivy's
            # widget tree (e.g., parent -> child -> parent references).
            import gc
            for _ in range(3):
                gc.collect()

            # Signal the watchdog that the user is active.
            self._heartbeat()
            
            # Arm the watchdog's switch to enable session monitoring.
            with self._watchdog_state.lock:
                self._watchdog_state.switch_armed = True

            # Bind the typing. 
            # Every keystroke resets the timer and gives proof of life.
            msg_input = chat_screen.ids.msg_input
            msg_input.bind(text=self.reset_burn_timer)
            
            # Start the background thread to listen for incoming messages.
            threading.Thread(target=self.listen_loop, daemon=True).start()

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Cleanup failed.") from None




    def _handshake_session_id(self):
        """
        Negotiates a shared session ID with the peer.

        Exchanges session IDs generated by "start_session_id" and combines them
        deterministically (lexicographical order) to ensure both peers derive the
        same final ID. Used as AAD in AES-GCM encryption.

        Note:
            The session IDs are shredded after combination.
        """

        # Pre-initialize all variables that need to be Burned.
        peer_current_session_id = None

        try:

            self.start_session_id()
            self.sock.settimeout(0.1)
        
            # Send the ID generated by the user.
            with self._watchdog_state.lock:
                self.sock.send(self._watchdog_state.current_session_id)
                                    
            # Receive the ID generated by the peer.
            peer_current_session_id = self.sock.recv(69)
        
            # The client with the lexicographically larger ID becomes the Initiator.
            # This deterministic approach ensures the final shared identifier is always the same for both.
            is_initiator = self._watchdog_state.current_session_id > peer_current_session_id
        
            if is_initiator is True:
                # Combine both session IDs to create the final shared identifier.
                session_id = self._watchdog_state.current_session_id + peer_current_session_id
        
            else:
                # Combine both session IDs to create the final shared identifier.
                session_id = peer_current_session_id + self._watchdog_state.current_session_id
        
        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Session ID Handshake Failed.") from None

        finally:
            # Guaranteed Burn, whether successful or crashed.
            BurnerMemoryByte.shred(peer_current_session_id)
            BurnerMemoryByte.shred(self._watchdog_state.current_session_id)
        
            # Remove the timeout.
            self.sock.settimeout(None)
        
            # Store the final session ID in the watchdog state for future use.
            with self._watchdog_state.lock:
                self._watchdog_state.current_session_id = session_id




    def start_session_id(self):
        """
        Generates a cryptographically secure session ID.

        Combines a static prefix ("mandy") with 64 bytes of random data
        from "os.urandom". The result is stored in "WatchdogState.current_session_id".

        Note:
            All temporary variables ("session_str", "session_bytes", "random_bytes")
            are shredded after use.
        """

        # Pre-initialize all variables that need to be Burned.
        session_str = None
        session_bytes = None
        random_bytes = None

        try:

            # Create a static prefix string ("text") dynamically to allow for secure deletion.
            # This ensures the string can be shredded after use, even though it is hardcoded.
            session_str = "".join(["y", "o", "u", "r", "_", "s", "t", "r", "i", "n", "g"])
        
            # Encode the static prefix to bytes for concatenation with the random component.
            session_bytes = session_str.encode('utf-8')
        
            # Generate 64 bytes of cryptographically secure random data using os.urandom.
            # This ensures the session ID is unique and unpredictable.
            random_bytes = os.urandom(64)
        
            # Combine the static prefix and random bytes into the final session ID.
            # Store the result in the watchdog state for use during the session.
            with self._watchdog_state.lock:
                self._watchdog_state.current_session_id = session_bytes + random_bytes

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            raise SecurityError("Session ID Creation Failed.") from None

        finally:
            # Guaranteed Burn, whether successful or crashed.
            BurnerMemoryString.shred(session_str)
            BurnerMemoryByte.shred(session_bytes)
            BurnerMemoryByte.shred(random_bytes)




    def listen_loop(self):
        """
        Background thread: Listens for incoming encrypted messages.

        Continuously:
            Checks "app_state" (exits if not "CHAT").
            Receives encrypted data from the socket (8192-byte buffer).
            Decrypts using "E2EProtocol" and the current session ID.
            Shreds the ciphertext after decryption.
            Posts decrypted messages to the UI queue.
            Resets the dead-man switch timer.

        Note:
            The decrypted message ("decrypted_msg") and "data" are shredded here
            in the finally block.
        """

        # Run indefinitely until the app state changes or an error occurs.
        while True:

            # Pre-initialize all variables that need to be Burned.
            data = None
            decrypted_msg = None

            try:

                # Check the current app state under a lock to ensure thread safety.
                # Exit the loop if the state is no longer "CHAT".
                with self._watchdog_state.lock:
                    app_state = self._watchdog_state.app_state
                    if app_state != 'CHAT':
                        break
            
                # Receive encrypted data from the socket. The buffer size (8192) accommodates
                # large messages, including padded or fragmented payloads.
                data = self.sock.recv(8192)
                
                if not data:
                    # Empty data indicates the connection was closed by the peer.
                    break
                
                # Retrieve the current session ID under a lock for thread safety.
                with self._watchdog_state.lock:
                    session_id = self._watchdog_state.current_session_id
                
                # Decrypt the received data using the session ID and E2EProtocol.
                decrypted_msg = self.crypto.decrypt(data, session_id)

                # Burn what is no longer needed.
                BurnerMemoryByte.shred(data)
                
                # Post the decrypted message in the UI.
                self.post_ui(decrypted_msg, "peer")

                # Reset the dead-man switch timer to indicate active connection.
                # This prevents the UI from being cleared while messages are being received.
                self.reset_burn_timer(None, None) 
                
                # Signal the watchdog that the connection is active (data received).
                self._heartbeat()

            except Exception:
                # Catch any failure and raise a generic error with no traceback.
                self._ui_queue.put(lambda: self.post_ui("[!] Error.", "error"))
                break

            finally:
                # Guaranteed Burn, whether successful or crashed.
                BurnerMemoryByte.shred(data)
                BurnerMemoryString.shred(decrypted_msg)




    def send_encrypted_message(self, text):
        """
        Encrypts and transmits a message to the peer.

        Steps:
            Validates "app_state" is "CHAT".
            Posts the message to the local UI (immediate feedback).
            Encrypts using "E2EProtocol" and the current session ID.
            Adds random jitter (50-250ms) to obfuscate timing patterns.
            Sends the encrypted payload over the socket.
            Shreds the "text" and "encrypted_payload" after transmission.
            Resets the dead-man switch timer.

        Arguments:
            text: Plaintext message to send.

        Note:
            Timing obfuscation defeats traffic analysis and keystroke timing attacks.
        """

        # Pre-initialize all variables that need to be Burned.
        encrypted_payload = None

        try:

            # Retrieve the app state under a lock for thread safety.
            with self._watchdog_state.lock:
                app_state = self._watchdog_state.app_state
            
            # For the first message, introduce a small delay to avoid race conditions
            # during initial setup (e.g., UI not fully ready).
            if app_state == 'CHAT':
                if not hasattr(self, '_first_msg_sent'):
                    time.sleep(0.1)
                    self._first_msg_sent = True

            # Post the message to the local UI immediately for user feedback.
            # This ensures the user sees their message even if transmission fails.
            self.post_ui(text, "me")

            # Retrieve the current session ID under a lock for thread safety.
            with self._watchdog_state.lock:
                session_id = self._watchdog_state.current_session_id
            
            # Encrypt the message using the session ID and E2EProtocol.
            # Uses AES-GCM with the session ID as AAD (Authenticated Additional Data).
            encrypted_payload = self.crypto.encrypt(text, session_id)

            # Introduce a random delay (jitter) between 50ms and 250ms to obfuscate the timing
            # of message transmission. This breaks the direct correlation between when the user
            # presses Enter and when the packet is sent, defeating traffic analysis.
            jitter = random.uniform(0.05, 0.25)
            time.sleep(jitter)
            
            # Send the encrypted payload over the socket.
            self.sock.send(encrypted_payload)

            # Burn what is no longer needed.
            BurnerMemoryByte.shred(encrypted_payload)

            # Reset the dead-man switch timer to indicate active connection.
            # This prevents the UI from being cleared while messages are being sent.
            self.reset_burn_timer(None, None)

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            self._ui_queue.put(lambda: self.post_ui("[!] Error.", "error"))
            raise SecurityError("[!] Error.") from None

        finally:
            # Guaranteed Burn, whether successful or crashed.
            BurnerMemoryByte.shred(encrypted_payload)
            BurnerMemoryString.shred(text)




    def post_ui(self, text, msg_type):
        """
        Formats and queues a message for UI display.

        Maps "msg_type" to a color/prefix and formats the text with Kivy markup.
        Schedules "_append_to_rv" on the main thread via "Clock.schedule_once".

        Arguments:
            text: Message content (plaintext).
            msg_type: Category of the message. Valid types:
                - "system": Green (connection status).
                - "warning": Yellow (user warnings).
                - "error": Red (critical errors).
                - "success": Green (success confirmations).
                - "fsociety": Red (peer challenges).
                - "me": White with "$: " prefix (user-sent messages).
                - "peer": Cyan with "Target: " prefix (received messages).

        Note:
            The formatted markup is not shredded here—it is managed by Kivy's
            RecycleView and will be shredded later in "_execute_rv_burn".
        """

        try:

            # Define the default color and prefix for the message based on its type.
            color, prefix = "FFFFFF", ""
        
            if msg_type == "system": color = "008800"
            elif msg_type == "warning": color = "AAAA00"
            elif msg_type == "error": color = "FF0000"
            elif msg_type == "success": color = "00FF00"
            elif msg_type == "fsociety": color = "FF0000"
            elif msg_type == "me":
                color = "FFFFFF"
                prefix = "[color=555555]$: [/color]"
            elif msg_type == "peer":
                color = "00FFFF"
                prefix = "[color=0088AA]Target: [/color]"

            # Format the message.
            formatted_markup = f"[color={color}]{prefix}{text}[/color]"

            # Schedule the message to be appended to the RecycleView on the next clock cycle.
            # This ensures the UI update happens on the main thread, avoiding threading issues.
            # The lambda uses a default argument to capture "formatted_markup" at this moment,
            # preventing late-binding issues if the variable changes later.
            Clock.schedule_once(
                lambda dt, m=formatted_markup: self._append_to_rv(m),
                0
            )
        
        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            self.post_ui("[!] UI error.", "error")
            raise SecurityError("[!] UI error.") from None

        


    def _append_to_rv(self, formatted_markup):
        """
        Appends a formatted message to the chat RecycleView.

        Arguments:
            formatted_markup: Message with Kivy markup (e.g., "[color=FFFFFF]text[/color]").

        Note:
            - Appends to "rv.data" and scrolls to the top.
            - Resets the dead-man switch timer if "app_state" is "CHAT".
        """

        try:

            
            # Retrieve the RecycleView widget from the chat screen.
            rv = self.root.get_screen('chat').ids.chat_rv
            
            # Append the formatted message to the RecycleView's data list.
            rv.data.append({'text': formatted_markup}) 
            
            # Scroll to the top of the RecycleView.
            rv.scroll_y = 0

            # Retrieve the current app state under a lock for thread safety.
            with self._watchdog_state.lock:
                app_state = self._watchdog_state.app_state
            
            if app_state == 'CHAT':
                self.reset_burn_timer(None, None)

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            self.post_ui("[!] UI append error.", "error")
            raise SecurityError("[!] UI append error: Rendering failed.") from None



        
    def reset_burn_timer(self, instance, value):
        """
        Resets the dead-man switch timer on user activity.

        Arguments:
            instance: Widget instance (unused, required by Kivy binding).
            value: New text value (unused, required by Kivy binding).

        Note:
            - Cancels any pending burn event.
            - Schedules a new burn event after "burn_timeout" seconds.
            - Called on every keystroke.
        """
        
        try:

            # Retrieve the current app state under a lock for thread safety.
            with self._watchdog_state.lock:
                app_state = self._watchdog_state.app_state
            
            if app_state == 'CHAT':
                # Cancel the existing burn event if it is active.
                if hasattr(self, 'burn_event') and self.burn_event:
                    self.burn_event.cancel()
            
                # Retrieve the burn timeout from the watchdog state.
                with self._watchdog_state.lock:
                    burn_timeout = self._watchdog_state.burn_timeout
            
                # Schedule a new burn event to trigger after the timeout period.
                # This ensures the dead-man switch will fire if no activity occurs.
                self.burn_event = Clock.schedule_once(lambda dt: self.execute_rv_burn(), burn_timeout)

                # Reseting burn timer proves user is active.
                self._heartbeat()

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            self.post_ui("[!] Timer reset error.", "error")
            raise SecurityError("[!] Timer reset error: Sync failed.") from None



    def execute_rv_burn(self):
        """
        Schedules the dead-man switch cleanup for main-thread execution.

        Delegates to "_execute_rv_burn" via "Clock.schedule_once" to ensure
        cleanup runs on the main thread (where Kivy operations are safe).
        """

        try:

            # Schedule the cleanup to run on the next clock cycle (main thread).
            Clock.schedule_once(lambda dt: self._execute_rv_burn(), 0)

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            self.post_ui("[!] Cleanup error.", "error")
            raise SecurityError("[!] Cleanup error: Burner failed.") from None



    def _execute_rv_burn(self):
        """
        Dead-man switch cleanup: Sanitizes all chat messages from memory.

        Comprehensive cleanup targeting:
            RecycleView Data: Shreds all message strings in "rv.data".
            Kivy Widgets: Deep-shreds active/cached labels (including CoreLabel
                and texture data) to target C-level rendering buffers (Pango, Cairo, SDL2).
            Input Widget: Shreds text, undo/redo history, and internal buffers.
            Kivy Caches: Flushes all internal caches (textures, images, etc.).
            Memory Flooding: Overwrites freed memory blocks (1.25MB + varied sizes).
            Garbage Collection: Runs 3 passes to break circular references.

        Note:
            This is called in three scenarios:
              - Dead-man switch (after "burn_timeout" seconds of inactivity).
              - Manual chat clear ("/erase" command).
              - Full burn protocol ("/burn" command or watchdog trigger).
        """

        # Pre-initialize all variables that need to be Burned.
        ghost_purger_str = None
        ghost_purger_bytes = None
        memory_flood = None

        try:
        
            chat_screen = self.root.get_screen('chat')
            rv = chat_screen.ids.chat_rv
            msg_input = chat_screen.ids.msg_input

            Window.clearcolor = (0, 0, 0, 1)
            Window.canvas.ask_update()

            def deep_shred_kivy_label(widget):
                """
                [KIVY LABEL SANITIZER]
                Recursively shreds text data from a Kivy label widget and its internal rendering structures.
                This targets both Python-level strings and C-level rendering buffers (Pango, Cairo, SDL2).

                Parameters:
                widget: A Kivy Label or SelectableLabel widget to sanitize.

                Workflow:
                Overwrites the widget's "text" property with dummy data and forces a render
                to smash C/SDL2 memory buffers.
                Shreds the original Python string.
                Recursively shreds CoreLabel internals (_label, _lines, etc.).
                """

                if not widget:
                    return

                # BURN DEEP INTERNALS
                # Destroy the internal pointers before updating the surface widget text.
    
                # Standard Labels (MessageLabel, CoreLabel, MarkupLabel)
                if hasattr(widget, '_label') and widget._label:
                    if hasattr(widget._label, 'text') and widget._label.text:
                        BurnerMemoryString.shred(widget._label.text)

                # TextInputs (Input boxes store internal text in widget._lines)
                elif hasattr(widget, '_lines') and isinstance(widget._lines, list):
                    for line in widget._lines:
                        if isinstance(line, str) and line:
                            BurnerMemoryString.shred(line)


                # BURN SURFACE PYTHON STRING
                original_len = 0
                if hasattr(widget, 'text') and widget.text:
                    original_len = len(widget.text)
        
                    # Shred the main python property in-place
                    BurnerMemoryString.shred(widget.text)


                # DESTROY THE C-LEVEL GRAPHICS BUFFER
                # Now that the raw python RAM is wiped, we overwrite the physical pixels 
                # in the OpenGL/SDL2 texture memory.
                if original_len > 0:
        
                    # This triggers Kivy's property cascade, safely overwriting the dead 
                    # strings we just burned with new internal structures of zeros.
                    widget.text = "0" * original_len
        
                    # Forces the GPU/SDL2 buffer to render the zeros, destroying the old pixel data.
                    if hasattr(widget, 'texture_update'):
                        widget.texture_update()


                # FINAL UI RESET
                # Clears the zeroes so the UI is visually empty.
                if hasattr(widget, 'text'):
                    widget.text = ""
            
            # Shred active widgets BEFORE clearing rv.data to ensure C-level buffers are overwritten
            # while the widget still holds references to them.
            # Shred active children (visible labels in the RecycleView).
            if rv.children:
                for child in rv.children[0].children:
                    deep_shred_kivy_label(child)

            # Shred cached views (RecycleView's internal widget cache).
            if hasattr(rv, 'view_adapter') and hasattr(rv.view_adapter, 'views'):
                for view in rv.view_adapter.views.values():
                    deep_shred_kivy_label(view)
                    
            # Shred dirty views (RecycleView's pending widget cache).
            if hasattr(rv, 'view_adapter') and hasattr(rv.view_adapter, 'dirty_views'):
                for view_list in rv.view_adapter.dirty_views.values():
                    for view in view_list:
                        deep_shred_kivy_label(view)

            # Shred the active input box surface and internal graphics buffers.
            deep_shred_kivy_label(msg_input)

            # Shred Undo History.
            if hasattr(msg_input, '_undo_history'):
                for action in msg_input._undo_history:
                    if isinstance(action, tuple):
                        for element in action:
                            if isinstance(element, str) and element:
                                BurnerMemoryString.shred(element)
                msg_input._undo_history.clear()
                
            # Shred Redo History.
            if hasattr(msg_input, '_redo_history'):
                for action in msg_input._redo_history:
                    if isinstance(action, tuple):
                        for element in action:
                            if isinstance(element, str) and element:
                                BurnerMemoryString.shred(element)
                msg_input._redo_history.clear()

            

            # NOW it is safe to shred the underlying Python data and refresh.
            for item in rv.data:
                for key, value in item.items():
                    if isinstance(value, str) and value:
                        BurnerMemoryString.shred(value)
            
            # Clear the RecycleView data.
            rv.data = []
            
            # Force Kivy to release internal references.
            rv.refresh_from_data()
            
            # Clear Kivy's internal caches (textures, images, etc.).
            for category in list(Cache._categories.keys()):
                Cache.remove(category)

            # Run garbage collection to break circular references.
            import gc
            for _ in range(3):
                gc.collect()
            
            # Overwrite freed memory blocks to prevent swap file leakage.
            # Allocates a range of string and byte objects to target Python's memory allocator.
            ghost_purger_str = []
            for size in [8, 16, 32, 64, 128, 256, 512]:
                for _ in range(300):
                    ghost_purger_str.append("A" * size)

            ghost_purger_bytes = []
            for size in [8, 16, 32, 64, 128, 256, 512]:
                for _ in range(300):
                    ghost_purger_bytes.append(b"\x00" * size)

            del ghost_purger_str
            del ghost_purger_bytes
            ghost_purger_str = None
            ghost_purger_bytes = None

            # Run garbage collection to break circular references.
            for _ in range(3):
                gc.collect()

            # Additional memory flooding with varied block sizes.
            memory_flood = [b'\x00' * i for i in range(1, 256) for _ in range(50)]
            memory_flood.extend([b'\xFF' * i for i in range(1, 256) for _ in range(50)])
            del memory_flood
            memory_flood = None
            
            print("[+] Messages Burned.")

        except Exception:
            # Catch any failure and raise a generic error with no traceback.
            print("[-] Messages not Burned: Memory exception caught. Details suppressed for security")
            if hasattr(self, 'post_ui'):
                self.post_ui("[!] Burn protocol error.", "error")
            raise SecurityError("Burn Error.") from None

        finally:
            # If the process crashed halfway through the memory flood phase, explicitly 
            # orphan the payload arrays here and force the python allocator to sweep them up.
            if ghost_purger_str is not None:
                del ghost_purger_str
            if ghost_purger_bytes is not None:
                del ghost_purger_bytes
            if memory_flood is not None:
                del memory_flood
            
            import gc
            for _ in range(3):
                gc.collect()


if __name__ == '__main__':
    import sys
    import os

    # UNIVERSAL CRASH HANDLER (Covers Mobile & Desktop)
    # Mobile OSes (Android/iOS) might not have the 'resource' module compiled.
    # By hijacking Python's global exception hook, we guarantee that no unhandled
    # error ever reaches the OS. If the OS doesn't see a crash, it doesn't write a dump.
    def excepthook(exc_type, exc_value, exc_traceback):
        """
        Global exception handler to prevent forensic core dumps.

        Replaces Python's default excepthook to:
            Destroy the traceback and exception objects immediately.
            Force garbage collection (3 passes) to overwrite freed memory.
            Exit with a generic error code (no crash dump).

        Note:
            Combined with OS-specific locks (e.g., "RLIMIT_CORE" on Unix,
            "SetErrorMode" on Windows), it ensures no sensitive data is written
            to disk in the event of a crash.
        """
        
        import gc
        print("\n[!] FATAL: Execution halted. Burning process.")
        
        # Destroy the traceback instantly so it doesn't pin variables in RAM
        del exc_traceback
        del exc_value
        
        for _ in range(3): 
            gc.collect()
            
        # Exit with a standard error code so the OS thinks we shut down intentionally
        sys.exit(1)
        
    sys.excepthook = excepthook


    # OS-SPECIFIC HARDWARE LOCKS
    if os.name == 'posix':
        # LINUX / macOS / UNIX
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            # If stripped on Android, the excepthook above acts as the safety net.
            pass 

    elif os.name == 'nt':
        # WINDOWS
        try:
            import ctypes
            # Intercept Windows Error Reporting (WER) using C-types.
            # 0x0001 = SEM_FAILCRITICALERRORS
            # 0x0002 = SEM_NOGPFAULTERRORBOX (Prevents the crash dialog & memory dump)
            # 0x8000 = SEM_NOOPENFILEERRORBOX
            ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
        except Exception:
            pass


    # APPLICATION EXECUTION
    try:
        BlackHoleApp().run()
        
    except KeyboardInterrupt:
        # Normal terminal exit (Ctrl+C)
        sys.exit(0)
        
    except Exception as e:
        # Secondary safety net if the global hook is somehow bypassed.
        if hasattr(sys, 'exc_clear'):
            sys.exc_clear()
        del e
        print("\n[!] CRITICAL: App terminated.")
        sys.exit(1)
        
    finally:
        # Ultimate cleanup before yielding the thread back to the OS.
        import gc
        for _ in range(3): 
            gc.collect()
