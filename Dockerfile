# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Create a user to run the application
RUN useradd -m -u 1000 user

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY --chown=user ./requirements.txt requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --upgrade pymongo

# Copy the application code to the container
COPY --chown=user . .

# Change to the non-root user
USER user

# Expose the port the app runs on
EXPOSE 7680

# Command to run the application
CMD ["gunicorn", "app:app", "-b", "0.0.0.0:7680"]
