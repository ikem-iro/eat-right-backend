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

class Review(ReviewCreate, table=True):
    id: int = Field(default=None, primary_key=True)
    user_id: int = Field(default=None)
