# lab4/forms.py
from django import forms

class KeyForm(forms.Form):
    key_size = forms.ChoiceField(choices=[(2048, "2048"), (3072, "3072"), (4096, "4096")], initial=2048)

class FileUploadForm(forms.Form):
    file = forms.FileField()
