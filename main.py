from reduct_and_restore_PII import PIIMiddleware
from langchain_ollama import ChatOllama
import time
from dotenv import load_dotenv



load_dotenv()

request = """
Create a proposal for Ahmed from Microsoft.
The project will be managed by Sarah Johnson.
Contact Ahmed at ahmed@example.com.
"""


# Initialize the LLM and the PII middleware
llm = ChatOllama(
    model="gpt-oss:120b-cloud",
    temperature=0
)
middleware = PIIMiddleware()


def secure_llm_call(user_input: str):
    # ============ 1. Detect + pseudonymize ============
    start_anonymize = time.perf_counter()
    
    sanitized_input, mapping = middleware.anonymize(user_input)
    
    end_anonymize = time.perf_counter()
    print(f"Anonymization took {end_anonymize - start_anonymize:.4f} seconds")

    print("Sanitized Input:", sanitized_input)
    print("Mapping:", mapping)

    
    # ============ 2. Send ONLY sanitized data to LLM ============
    start_llm = time.perf_counter()
    
    response = llm.invoke(
        sanitized_input
    )
    
    end_llm = time.perf_counter()
    print(f"LLM call took {end_llm - start_llm:.4f} seconds")

    start_restore = time.perf_counter()

    # ============ 3. Restore original values ============
    final_response = middleware.restore(
        response.content,
        mapping
    )
    end_restore = time.perf_counter()
    print(f"Restoration took {end_restore - start_restore:.4f} seconds")

    return final_response


secure_llm_call(request)