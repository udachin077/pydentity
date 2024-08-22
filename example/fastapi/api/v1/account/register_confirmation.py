from fastapi import Depends, Query, HTTPException
from fastapi.requests import Request
from pydantic import EmailStr

from example.fastapi.api.dependencies import UserManager
from example.fastapi.api.v1.account._router import router



