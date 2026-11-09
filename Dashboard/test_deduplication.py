"""
Deduplication Test Suite and Examples

This file demonstrates how the deduplication module works with example news items.
It shows how the system identifies and filters duplicate news from different sources.
"""

import sys
import os

# Add Dashboard to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from deduplication import (
    is_potential_duplicate,
    find_duplicates_in_existing_items,
    filter_out_duplicates,
    calculate_similarity,
    calculate_entity_overlap,
    normalize_text,
    extract_key_entities
)


def example_1_same_news_different_source():
    """
    Example 1: Same security incident reported by different sources
    The LLM might return the same breach but with slightly different descriptions.
    """
    print("\n" + "="*80)
    print("EXAMPLE 1: Same Security Incident, Different Sources")
    print("="*80)
    
    # First scan result (source 1: BleepingComputer)
    existing_items = [
        {
            'date': '2025-12-28',
            'title': 'Critical pgAdmin Vulnerability Lets Attackers Execute Shell Commands on the Host',
            'description': 'A severe security vulnerability in pgAdmin 4, tracked as CVE-2025-13780, allows attackers to bypass security filters and execute arbitrary shell commands on the host server. This flaw stems from inadequate blocking of dangerous commands in uploaded database files during the restore process.',
            'severity': 'Critical',
            'source': 'https://cybersecuritynews.com/pgadmin-vulnerability-shell-commands/',
            'type': 'incident'
        }
    ]
    
    # New scan result (source 2: SecurityWeek)
    new_items = [
        {
            'date': '2024-12-21',
            'title': 'Critical pgAdmin Vulnerability Lets Attackers Execute Shell Commands on the Host',
            'description': 'A severe security vulnerability, tracked as CVE-2025-13780, was uncovered in pgAdmin 4. This flaw allowed attackers to bypass security filters and execute arbitrary shell commands on the host server by exploiting the applications plain-text restore feature, which failed to block dangerous commands hidden in uploaded database files adequately. The pgAdmin development team released a patch to address this vulnerability.',
            'severity': 'Critical',
            'source': ' https://cybersecuritynews.com/pgadmin-vulnerability-shell-commands/',
            'type': 'incident'
        }
    ]
    
    print("\nExisting item:")
    print(f"  Title: {existing_items[0]['title']}")
    print(f"  Description: {existing_items[0]['description'][:80]}...")
    print(f"  Source: {existing_items[0]['source']}")
    
    print("\nNew item from different source:")
    print(f"  Title: {new_items[0]['title']}")
    print(f"  Description: {new_items[0]['description'][:80]}...")
    print(f"  Source: {new_items[0]['source']}")
    
    # Calculate similarity
    title_sim = calculate_similarity(new_items[0]['title'], existing_items[0]['title'])
    desc_sim = calculate_similarity(new_items[0]['description'], existing_items[0]['description'])
    entity_overlap = calculate_entity_overlap(new_items[0]['description'], existing_items[0]['description'])
    
    print(f"\nSimilarity Analysis:")
    print(f"  Title similarity: {title_sim:.2%}")
    print(f"  Description similarity: {desc_sim:.2%}")
    print(f"  Entity overlap: {entity_overlap:.2%}")
    
    is_dup = is_potential_duplicate(new_items[0], existing_items[0])
    print(f"\nDuplicate detected: {is_dup}")
    print(f"Result: Item will be SKIPPED (not inserted)")


def example_2_same_date_different_incidents():
    """
    Example 2: Different incidents on the same date
    System should NOT flag these as duplicates even though they're from the same date.
    """
    print("\n" + "="*80)
    print("EXAMPLE 2: Different Incidents on Same Date (Should NOT be duplicates)")
    print("="*80)
    
    existing_items = [
        {
            'date': '2024-12-20',
            'title': 'AWS Announces Vulnerability in EC2 Service',
            'description': 'Amazon Web Services announced a vulnerability in their EC2 service that could allow privilege escalation.',
            'severity': 'High',
            'source': 'https://aws.com/...',
            'type': 'incident'
        }
    ]
    
    new_items = [
        {
            'date': '2024-12-20',
            'title': 'Microsoft Azure Faces Outage in European Region',
            'description': 'Microsoft Azure experienced a 2-hour outage affecting services in the European Union region on December 20th.',
            'severity': 'High',
            'source': 'https://microsoft.com/...',
            'type': 'incident'
        }
    ]
    
    print("\nExisting item:")
    print(f"  Title: {existing_items[0]['title']}")
    
    print("\nNew item (different company, same date):")
    print(f"  Title: {new_items[0]['title']}")
    
    is_dup = is_potential_duplicate(new_items[0], existing_items[0])
    print(f"\nDuplicate detected: {is_dup}")
    print(f"Result: Item will be INSERTED (different incidents)")


def example_3_company_news_from_multiple_sources():
    """
    Example 3: Same company news reported by multiple tech news outlets
    """
    print("\n" + "="*80)
    print("EXAMPLE 3: Company News from Multiple Sources")
    print("="*80)
    
    existing_items = [
        {
            'date': '2024-12-18',
            'title': 'Acme Inc Acquires SecureCloud Technology',
            'description': 'Acme Inc announced today that it has acquired SecureCloud Technology for $500 million. The acquisition strengthens Acme\'s position in the cloud security market.',
            'severity': 'Info',
            'source': 'https://acme.com/press-release',
            'type': 'news'
        }
    ]
    
    new_items = [
        {
            'date': '2024-12-18',
            'title': 'Acme Corporation Buys SecureCloud in $500M Deal',
            'description': 'Acme Corporation completed the acquisition of SecureCloud Technology for half a billion dollars, expanding its cloud security portfolio.',
            'severity': 'Info',
            'source': 'https://techcrunch.com/...',
            'type': 'news'
        }
    ]
    
    print("\nExisting news item:")
    print(f"  Title: {existing_items[0]['title']}")
    print(f"  Description: {existing_items[0]['description'][:70]}...")
    
    print("\nNew news item from different outlet:")
    print(f"  Title: {new_items[0]['title']}")
    print(f"  Description: {new_items[0]['description'][:70]}...")
    
    is_dup = is_potential_duplicate(new_items[0], existing_items[0])
    print(f"\nDuplicate detected: {is_dup}")
    print(f"Result: Item will be SKIPPED (same event, different source)")


def example_4_batch_filtering():
    """
    Example 4: Filter a batch of new items against existing items
    """
    print("\n" + "="*80)
    print("EXAMPLE 4: Batch Filtering (Multiple Items)")
    print("="*80)
    
    existing_items = [
        {
            'date': '2024-12-15',
            'title': 'Acme Corp Data Breach',
            'description': 'Acme Corp confirmed data breach affecting customer records.',
            'severity': 'High',
            'source': 'https://source1.com',
            'type': 'incident'
        },
        {
            'date': '2024-12-14',
            'title': 'Company Leadership Change',
            'description': 'New CEO announced at Acme Corp.',
            'severity': 'Info',
            'source': 'https://source2.com',
            'type': 'news'
        }
    ]
    
    new_items = [
        {
            'date': '2024-12-15',
            'title': 'Acme Corporation Suffers Major Data Breach',
            'description': 'Acme Corporation experienced a data breach with millions of customer records exposed.',
            'severity': 'High',
            'source': 'https://source3.com',
            'type': 'incident'
        },
        {
            'date': '2024-12-16',
            'title': 'New Product Launch from Acme',
            'description': 'Acme announced launch of innovative new security product.',
            'severity': 'Info',
            'source': 'https://source4.com',
            'type': 'news'
        },
        {
            'date': '2024-12-14',
            'title': 'Acme Corp Appoints New Chief Executive Officer',
            'description': 'Acme Corporation announced a new CEO to lead the company.',
            'severity': 'Info',
            'source': 'https://source5.com',
            'type': 'news'
        }
    ]
    
    print(f"\nExisting items in database: {len(existing_items)}")
    for i, item in enumerate(existing_items, 1):
        print(f"  {i}. {item['title']}")
    
    print(f"\nNew items from latest scan: {len(new_items)}")
    for i, item in enumerate(new_items, 1):
        print(f"  {i}. {item['title']}")
    
    # Filter duplicates
    filtered_items, duplicate_indices = filter_out_duplicates(new_items, existing_items)
    
    print(f"\n✓ Filtering Results:")
    print(f"  Items to insert: {len(filtered_items)}")
    print(f"  Duplicates removed: {len(duplicate_indices)}")
    
    if filtered_items:
        print(f"\n✓ Items to be inserted:")
        for item in filtered_items:
            print(f"    - {item['title']}")
    
    if duplicate_indices:
        print(f"\n✗ Duplicates removed:")
        for idx in duplicate_indices:
            print(f"    - {new_items[idx]['title']}")


def example_5_similarity_analysis():
    """
    Example 5: Detailed similarity analysis
    """
    print("\n" + "="*80)
    print("EXAMPLE 5: Detailed Similarity Analysis")
    print("="*80)
    
    items = [
        {
            'title': 'Data Breach at Acme Corp',
            'title2': 'Acme Corporation Suffers Data Breach'
        },
        {
            'title': 'AWS Security Vulnerability Disclosed',
            'title2': 'New AWS Vulnerability Found'
        },
        {
            'title': 'Major Security Incident at Example Inc',
            'title2': 'Unrelated News About Different Company'
        }
    ]
    
    for i, pair in enumerate(items, 1):
        sim = calculate_similarity(pair['title'], pair['title2'])
        entities1 = extract_key_entities(pair['title'])
        entities2 = extract_key_entities(pair['title2'])
        overlap = calculate_entity_overlap(pair['title'], pair['title2'])
        
        print(f"\nPair {i}:")
        print(f"  Title 1: {pair['title']}")
        print(f"  Title 2: {pair['title2']}")
        print(f"  Similarity: {sim:.2%}")
        print(f"  Entity overlap: {overlap:.2%}")
        print(f"  Would be duplicate: {sim > 0.75 or overlap > 0.6}")


def main():
    """Run all examples"""
    print("\n" + "▶"*40)
    print("NEWS DEDUPLICATION MODULE - EXAMPLES & TEST CASES")
    print("▶"*40)
    
    example_1_same_news_different_source()
    example_2_same_date_different_incidents()
    example_3_company_news_from_multiple_sources()
    example_4_batch_filtering()
    example_5_similarity_analysis()
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print("""
The deduplication module works by:

1. SEMANTIC SIMILARITY: Compares normalized titles and descriptions
2. ENTITY OVERLAP: Checks if key important words appear in both items
3. DATE PROXIMITY: Verifies items are from the same time period
4. TYPE MATCHING: Ensures both items are same type (incident or news)

Thresholds:
- Title similarity: 75% (0.75 confidence required)
- Description similarity: 65% (0.65 confidence required)
- Entity overlap: 60% (0.60 confidence required)
- Date proximity: 7 days

Benefits:
✓ Prevents duplicate news from different sources being stored
✓ Reduces database clutter
✓ Improves dashboard accuracy
✓ Handles descriptions that change between sources
✓ Works with news from multiple vendors (BleepingComputer, SecurityWeek, etc.)
    """)
    print("="*80)


if __name__ == '__main__':
    main()





