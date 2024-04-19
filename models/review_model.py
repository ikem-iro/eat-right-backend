from sqlmodel import Field, SQLModel

class ReviewCreate(SQLModel):
    content: str = Field(
        min_length=5,
        max_length=500,
        description="Content of the review",
        title="Review Content"
    )
    rating: int = Field(
        ge=1,
        le=5,
        description="Rating of the review",
        title="Review Rating"
    )

class Review(SQLModel, table=True):
    id: int = Field(primary_key=True)
    content: str
    rating: int
