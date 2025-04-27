from django import template

register = template.Library()

@register.filter(name='split')
def split(value, arg):
    """
    Splits a string into a list on the given delimiter.
    Example usage: {{ value|split:"," }}
    """
    return value.split(arg) 