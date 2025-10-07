from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
import random
import math

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def cesaro(numbers, count):
    coprime = 0
    for _ in range(count):
        i, j = random.sample(numbers, 2)
        if gcd(i, j) == 1:
            coprime += 1
    probability = coprime / count
    pi_estimate = math.sqrt(6 / probability)
    return pi_estimate

def lcg_numbers(m, a, c, x, count):
    numbers = []
    for _ in range(count):
        x = (a*x + c)%m
        numbers.append(x)
    return numbers

def lcg_period(m, a, c, x):
    x0 = x
    n = 1
    x = (a*x0 + c) % m
    while x != x0:
        x = (a*x + c) % m
        n += 1
    return n

from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
import random
import math

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def cesaro(numbers, count):
    coprime = 0
    for _ in range(count):
        i, j = random.sample(numbers, 2)
        if gcd(i, j) == 1:
            coprime += 1
    probability = coprime / count
    pi_estimate = math.sqrt(6 / probability)
    return pi_estimate

def lcg_numbers(m, a, c, x, count):
    numbers = []
    for _ in range(count):
        x = (a*x + c) % m
        numbers.append(x)
    return numbers

def lcg_period(m, a, c, x):
    x0 = x
    n = 1
    x = (a*x0 + c) % m
    while x != x0:
        x = (a*x + c) % m
        n += 1
    return n

def generate_lcg(request):
    result = None
    error = None

    if request.method == 'GET' and ('count' in request.GET or 'count_estimate' in request.GET):
        try:
            count = int(request.GET.get('count', 100))
            count_estimate = int(request.GET.get('count_estimate', 100000))

            if count <= 1 or count_estimate <= 1:
                raise ValueError("Числа повинні бути більше одиниці ")
            if count > 100_000:
                raise ValueError("Значення для генерації чисел більше 100 000")
            if count_estimate > 10_000_000:
                raise ValueError("Значення для оцінки π більше 10 000 000")
        except ValueError as e:
            error = f"Невірний ввід: {str(e)}"
        else:
            m = 2**13 - 1
            a = 5**5
            c = 3
            x0 = 16

            numbers = lcg_numbers(m, a, c, x0, count)
            period = lcg_period(m, a, c, x0)
            cesaro_estimate = cesaro(numbers, count_estimate)
            lib_numbers = [random.randint(1, m) for _ in range(273)]
            cesaro_lib = cesaro(lib_numbers, count_estimate)

            result = {
                'numbers': numbers,
                'lcg_period': period,
                'cesaro_estimate': cesaro_estimate,
                'cesaro_lib_estimate': cesaro_lib
            }

    return render(request, 'lcg/lcg.html', {'result': result, 'error': error})
