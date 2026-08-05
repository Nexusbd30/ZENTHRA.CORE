from fastapi import APIRouter

router = APIRouter()


@router.get("/items")
def startup():
    return {"ok": True}


@router.post(path="/dynamic")
async def create_item():
    return {"ok": True}

