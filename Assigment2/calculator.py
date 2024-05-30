import math
import random
import operator
from abc import ABC, abstractmethod
from collections import UserDict
import enum
import numbers
import typing

# ========================================================================
# ============================ Calculator API ============================
# ========================================================================

# region Calculator API

class Expression(ABC):
    '''
    Abstract class for all expressions
    '''

    @abstractmethod
    def __str__(self) -> str:
        pass

    # Default implementation ignores brackets, only special cases override this
    def __str_brackets__(self, brackets: bool) -> str:
        return str(self)


class Constant(Expression):
    '''
    Constant defines a the most basic building block of an expression
    '''

    def __init__(self, value: numbers.Real) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(value={self.value})'

    def __str__(self) -> str:
        return str(self.value)


# Type fallbacks - used to convert unknown types to expressions
Type_Fallbacks = {
    numbers.Real: Constant,
}
# Should be typing.Union[Expression, *Type_Fallbacks.keys()] but only works in Python 3.11
Expr = typing.Union[Expression, numbers.Real]


def type_fallback(var: typing.Any) -> Expression:
    '''
    Function which converts a variable to an expression.
    If the variable's type is not defined in Type_Fallbacks, a TypeError is raised.
    '''
    if isinstance(var, Expression):
        return var
    for key, value in Type_Fallbacks.items():
        if isinstance(var, key):
            return value(var)
    raise TypeError(
        f'Unknown expression type {type(var)} cannot be converted to Expression')


class Operator(ABC):
    '''
    Abstract class for all operators (binary and unary, and functions)
    '''
    @abstractmethod
    def __apply__(self) -> Expr:
        '''
        Abstract method for applying the operator to the arguments
        '''
        pass

    @abstractmethod
    def __call__(self) -> Expression:
        '''
        Abstract method for calling the operator, currently used to build an expression given the arguments and the 'self' operator
        '''
        pass

    @property
    @abstractmethod
    def get_symbol(self) -> str:
        '''
        Abstract property for getting the symbol of the operator
        '''
        pass

    def __str__(self) -> str:
        return self.get_symbol


class NamedConstant(Expression):
    '''
    NamedConstant defines a constant with a name (e.g. pi = 3.1415...)
    '''

    def __init__(self, name: str, value: Expr) -> None:
        self.name = name
        self.value = value

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(name={self.name}, value={self.value})'

    def __str__(self) -> str:
        return self.name


class Associativity(enum.Enum):
    '''
    Enum for associativity of operators
    '''
    LEFT = 0
    RIGHT = 1


class BinaryOperator(Operator):
    '''
    A Binary operator (e.g. +, -, *, /, etc.) is called with two operands
    Default associativity is left-associative
    '''

    def __init__(self, symbol: str, function: typing.Callable[[Expr, Expr], Expr], associativity: Associativity = Associativity.LEFT) -> None:
        self.symbol = symbol
        self.function = function
        self.associativity = associativity

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(symbol={self.symbol}, function={self.function}, associativity={self.associativity})'

    def __apply__(self, left_operand: Expr, right_operand: Expr) -> Expr:
        return type_fallback(self.function(type_fallback(left_operand), type_fallback(right_operand)))

    def __call__(self, left_operand: Expr, *right_operands: Expr) -> Expression:
        right_operand, *rest = right_operands
        if len(right_operands) == 0:
            # return type_fallback(left_operand) # (1)
            raise TypeError(
                f'Binary operator {self} called with only one operand')
        if len(right_operands) == 1:  # (2)
            return BinaryExpr(left_operand, self, right_operand)

        if self.associativity == Associativity.RIGHT:
            return BinaryExpr(left_operand, self, self(right_operand, *rest))
        return self(self(left_operand, right_operand), *rest)

    @property
    def get_symbol(self) -> str:
        return self.symbol


class BinaryExpr(Expression):
    '''
    A Binary expression is an expression of the form <Expression1> <BinaryOperator> <Expression2> 
    (where <Expression1> and <Expression2> are left and right operands respectively)
    '''

    def __init__(self, left_operand: Expr, operator: BinaryOperator, right_operand: Expr) -> None:
        self.left_operand = type_fallback(left_operand)
        self.operator = operator
        self.right_operand = type_fallback(right_operand)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(left_operand={self.left_operand}, operator={self.operator}, right_operand={self.right_operand})'

    def __str__(self) -> str:
        left = str(self.left_operand)
        right = str(self.right_operand)
        if isinstance(self.left_operand, BinaryExpr):
            left = f'({left})'
        if isinstance(self.right_operand, BinaryExpr):
            right = f'({right})'
        return f'{left} {self.operator.symbol} {right}'

    def __str_brackets__(self, brackets: bool) -> str:
        return f'({self.left_operand.__str_brackets__(brackets)} {self.operator.symbol} {self.right_operand.__str_brackets__(brackets)})'


class UnaryOperator(Operator):
    '''
    A Unary operator (e.g. -) is called with one operand
    '''

    def __init__(self, symbol: str, function: typing.Callable[[Expr], Expr]) -> None:
        self.symbol = symbol
        self.function = function

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(symbol={self.symbol}, function={self.function})'

    def __apply__(self, operand: Expr) -> Expr:
        return type_fallback(self.function(type_fallback(operand)))

    def __call__(self, operand: Expr) -> Expression:
        return UnaryExpr(self, operand)

    @property
    def get_symbol(self) -> str:
        return self.symbol


class UnaryExpr(Expression):
    '''
    A Unary expression is an expression of the form <UnaryOperator> <Expression>
    '''

    def __init__(self, operator: UnaryOperator, operand: Expr) -> None:
        self.operator = operator
        self.operand = type_fallback(operand)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(operand={self.operand}, operator={self.operator})'

    def __str__(self) -> str:
        return f'{self.operator.symbol}{str(self.operand)}'

    def __str_brackets__(self, brackets: bool) -> str:
        return f'{self.operator.symbol}({self.operand.__str_brackets__(brackets)})'


class FunctionProtocol(typing.Protocol):
    '''
    Protocol for functions that can be used in expressions, must be callable with any number of arguments which are all expressions
    '''

    def __call__(self, *args: Expr) -> Expr: ...


class Function(Operator):
    '''
    General function class, can be called with any number of arguments
    '''

    def __init__(self, name: str, function: FunctionProtocol) -> None:
        self.name = name
        self.function = function

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(name={self.name}, function={self.function})'

    def __apply__(self, *args: Expr) -> Expr:
        return type_fallback(self.function(*[type_fallback(arg) for arg in args]))

    def __call__(self, *args: Expr) -> Expression:
        return FunctionCallExpr(self, *args)

    @property
    def get_symbol(self) -> str:
        return self.name


class FunctionCallExpr(Expression):
    '''
    A function call expression is an expression of the form <Function> (<Expression1>, <Expression2>, ..., <ExpressionN>)
    '''

    def __init__(self, function: Function, *args: Expr) -> None:
        self.function = function
        self.args = [type_fallback(arg) for arg in args]

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(function={self.function}, args={self.args})'

    def __str__(self) -> str:
        return f'{self.function.name}({", ".join(map(str, self.args))})'

    def __str_brackets__(self, brackets: bool) -> str:
        return f'{self.function.name}({", ".join(map(lambda arg: arg.__str_brackets__(brackets), self.args))})'

# endregion


# ========================================================================
# =============================== Helpers ================================
# ========================================================================

# region Helpers

def stringify(expression: Expr, add_brackets: bool = False) -> str:
    expr = type_fallback(expression)
    if add_brackets:
        expr_s = expr.__str_brackets__(True)
    else:
        expr_s = str(expr)
    # Remove unnecessary brackets
    matchings = {}
    stack = []
    for i, char in enumerate(expr_s):
        if char in '(':
            stack.append(i)
        elif char in ')':
            if not stack:
                raise ValueError(f'Unmatched closing bracket at position {i}')
            matchings[stack.pop()] = i
    if stack:
        raise ValueError(
            f'Unmatched opening bracket at position {stack.pop()}')
    for left, right in matchings.copy().items():
        if (left+1) in matchings and matchings[left+1] == right-1:
            expr_s = expr_s[:left] + expr_s[left+1:right-1] + expr_s[right:]
    if 0 in matchings and matchings[0] == len(expr_s)-1:
        expr_s = expr_s[1:-1]
    return expr_s

# endregion


# ========================================================================
# ============================= Predefined ===============================
# ========================================================================

# region Predefined


class __NamedConstantDict__(dict):
    def __getattr__(self, name: str) -> NamedConstant:
        return self[name]

    def __setattr__(self, name: str, value: Expr) -> None:
        self[name] = NamedConstant(name, value)


NAMED_CONSTANTS = __NamedConstantDict__()
NAMED_CONSTANTS.PI = math.pi
NAMED_CONSTANTS.TAU = math.tau
NAMED_CONSTANTS.E = math.e

T = typing.TypeVar('T', bound=Operator)


class __OperationDict__(UserDict, typing.Generic[T]):
    def __getattr__(self, name: str) -> T:
        return self[name]

    def __setattr__(self, name: str, value: T) -> None:
        if isinstance(value, Operator):
            self[name] = value
        else:
            super().__setattr__(name, value)


BINARY_OPERATORS = __OperationDict__[BinaryOperator]()
BINARY_OPERATORS.ADD = BinaryOperator('+', operator.add)
BINARY_OPERATORS.SUB = BinaryOperator('-', operator.sub)
BINARY_OPERATORS.MUL = BinaryOperator('*', operator.mul)
BINARY_OPERATORS.DIV = BinaryOperator('/', operator.truediv)
BINARY_OPERATORS.MOD = BinaryOperator('%', operator.mod)
BINARY_OPERATORS.POW = BinaryOperator('**', operator.pow, Associativity.RIGHT)

UNARY_OPERATORS = __OperationDict__[UnaryOperator]()
UNARY_OPERATORS.NEG = UnaryOperator('-', operator.neg)
UNARY_OPERATORS.POS = UnaryOperator('+', operator.pos)

FUNCTIONS = __OperationDict__[Function]()
FUNCTIONS.SIN = Function('sin', math.sin)
FUNCTIONS.COS = Function('cos', math.cos)
FUNCTIONS.TAN = Function('tan', math.tan)
FUNCTIONS.SQRT = Function('sqrt', math.sqrt)
FUNCTIONS.LOG = Function('log', math.log)
FUNCTIONS.MAX = Function('max', max)
FUNCTIONS.MIN = Function('min', min)
FUNCTIONS.POW = Function('pow', pow)
FUNCTIONS.RAND = Function('rand', random.uniform)

# endregion
