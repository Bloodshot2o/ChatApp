from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from .models import Message
from django.contrib.auth.decorators import login_required
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os


# Encryption function
def encrypt_message(key, message):
    key = key.ljust(32, b'\0')  # Ensure key is 32 bytes long
    iv = os.urandom(16)  # Generate a random 16-byte initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad message to be a multiple of block size (16 bytes for AES)
    padding = 16 - len(message) % 16
    message += chr(padding) * padding
    
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    encrypted_message = b64encode(iv + encrypted_message).decode('utf-8')
    return encrypted_message

# Decryption function
def decrypt_message(key, encrypted_message):
    encrypted_message = b64decode(encrypted_message)
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    
    key = key.ljust(32, b'\0')  # Ensure key is 32 bytes long
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    padding = decrypted_message[-1]
    return decrypted_message[:-padding].decode('utf-8')

# Registration View
def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            # Example: Encrypt user data (e.g., username or email)
            encryption_key = 'your-secret-key'  # Use a strong key in production
            encrypted_username = encrypt_message(encryption_key, user.username)
            
            # Store the encrypted username or other sensitive data as needed
            user.profile.encrypted_username = encrypted_username
            user.profile.save()
            
            # Authenticate and log the user in
            user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password1'])
            login(request, user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})

# Login View
def login_view(request):
    if request.method == 'POST':
        # Get the encrypted username from the profile (just as an example)
        user = authenticate(username=request.POST['username'], password=request.POST['password'])
        
        if user:
            # Example: Decrypt the username
            encryption_key = 'your-secret-key'  # Use the same key as during encryption
            decrypted_username = decrypt_message(encryption_key, user.profile.encrypted_username)
            print(f"Decrypted username: {decrypted_username}")  # You can use this as needed
            
            login(request, user)
            return redirect('home')
        else:
            # Handle authentication failure
            pass
    
    return render(request, 'login.html')

# Messaging Views
@login_required
def send_message(request):
    if request.method == 'POST':
        receiver = User.objects.get(username=request.POST['receiver'])
        encryption_key = 'your-secret-key'  # Use a strong key in production
        
        # Encrypt the message before saving it
        encrypted_message = encrypt_message(request.user.username.encode(), request.POST['message'])
        
        # Save the encrypted message to the database
        Message.objects.create(sender=request.user, receiver=receiver, message=encrypted_message)
        
        return redirect('message_history')

    return render(request, 'send_message.html')

@login_required
def message_history(request):
    messages = Message.objects.filter(receiver=request.user)
    decrypted_messages = []
    
    for msg in messages:
        decrypted_message = decrypt_message(request.user.username.encode(), msg.message)
        decrypted_messages.append({
            'sender': msg.sender.username,
            'message': decrypted_message,
            'timestamp': msg.timestamp
        })
    
    return render(request, 'message_history.html', {'messages': decrypted_messages})

def home(request):
    return HttpResponse("welcome to massaging page!")