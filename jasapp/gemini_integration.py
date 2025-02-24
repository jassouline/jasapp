import google.generativeai as genai


def generate_corrected_code(file_type, file_content, errors, api_key, detailed=False):
    """
    Generates a corrected version of the code using the Gemini API.

    Args:
        file_type (str): 'dockerfile' or 'kubernetes'.
        file_content (str): The content of the file to be corrected.
        errors (list): A list of error dictionaries.
        api_key (str): The Gemini API key.

    Returns:
        str: The corrected code, or None if an error occurred.
    """
    genai.configure(api_key=api_key)

    # Create the model
    generation_config = {
        "temperature": 0.25,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 8192,
        "response_mime_type": "text/plain",
    }

    model = genai.GenerativeModel(
        model_name="gemini-2.0-flash",
        generation_config=generation_config,
    )

    formatted_errors = "\n".join([f"- {error['message']} (Line {error.get('line', 'N/A')})" for error in errors])

    if detailed:
        prompt = f"""You are an expert in writing and correcting {file_type} files.
        Here is a {file_type} file:
        ```
        {file_content}
        ```

        Here are the linting errors found:
        {formatted_errors}

        Please provide a corrected version of the file, with explanations for each correction, in a markdown format.
        Only provide the corrected code between ```.
        """
    else:
        prompt = f"""You are an expert in writing and correcting {file_type} files.
        Here is a {file_type} file:
        ```
        {file_content}
        ```

        Here are the linting errors found:
        {formatted_errors}

        Please provide a corrected version of the file.
        Only provide the corrected code between ```.
        """
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini API error: {e}")
        return None  # Return None in case of error
