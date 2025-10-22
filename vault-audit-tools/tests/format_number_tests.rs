// Test format_number functions across different command modules
// These functions format numbers with thousand separators (e.g., 1234567 -> "1,234,567")

use vault_audit_tools::commands::airflow_polling;
use vault_audit_tools::commands::client_activity;
use vault_audit_tools::commands::entity_list;
use vault_audit_tools::commands::token_export;

// All format_number implementations should behave identically

#[test]
fn test_airflow_format_number_zero() {
    assert_eq!(airflow_polling::format_number(0), "0");
}

#[test]
fn test_airflow_format_number_small() {
    assert_eq!(airflow_polling::format_number(42), "42");
    assert_eq!(airflow_polling::format_number(999), "999");
}

#[test]
fn test_airflow_format_number_thousands() {
    assert_eq!(airflow_polling::format_number(1000), "1,000");
    assert_eq!(airflow_polling::format_number(5678), "5,678");
}

#[test]
fn test_airflow_format_number_millions() {
    assert_eq!(airflow_polling::format_number(1234567), "1,234,567");
    assert_eq!(airflow_polling::format_number(9876543), "9,876,543");
}

#[test]
fn test_client_activity_format_number_zero() {
    assert_eq!(client_activity::format_number(0), "0");
}

#[test]
fn test_client_activity_format_number_small() {
    assert_eq!(client_activity::format_number(123), "123");
    assert_eq!(client_activity::format_number(999), "999");
}

#[test]
fn test_client_activity_format_number_thousands() {
    assert_eq!(client_activity::format_number(1000), "1,000");
    assert_eq!(client_activity::format_number(12345), "12,345");
}

#[test]
fn test_client_activity_format_number_millions() {
    assert_eq!(client_activity::format_number(1000000), "1,000,000");
    assert_eq!(client_activity::format_number(9999999), "9,999,999");
}

#[test]
fn test_entity_list_format_number_billions() {
    assert_eq!(entity_list::format_number(1234567890), "1,234,567,890");
}

#[test]
fn test_all_implementations_consistent() {
    let test_values = vec![0, 1, 10, 100, 1000, 10000, 100000, 1000000];
    
    for value in test_values {
        let af_result = airflow_polling::format_number(value);
        let ca_result = client_activity::format_number(value);
        let el_result = entity_list::format_number(value);
        let te_result = token_export::format_number(value);
        
        assert_eq!(af_result, ca_result, "Airflow and ClientActivity differ for {}", value);
        assert_eq!(ca_result, el_result, "ClientActivity and EntityList differ for {}", value);
        assert_eq!(el_result, te_result, "EntityList and TokenExport differ for {}", value);
    }
}

#[test]
fn test_format_number_edge_cases() {
    // Test boundary values
    assert_eq!(airflow_polling::format_number(999), "999");
    assert_eq!(airflow_polling::format_number(1000), "1,000");
    assert_eq!(airflow_polling::format_number(999999), "999,999");
    assert_eq!(airflow_polling::format_number(1000000), "1,000,000");
}

#[test]
fn test_format_number_large_values() {
    assert_eq!(entity_list::format_number(usize::MAX), {
        // Format MAX value with commas
        let s = usize::MAX.to_string();
        let mut result = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        result.chars().rev().collect::<String>()
    });
}

#[test]
fn test_token_export_format_number() {
    assert_eq!(token_export::format_number(0), "0");
    assert_eq!(token_export::format_number(500), "500");
    assert_eq!(token_export::format_number(5000), "5,000");
    assert_eq!(token_export::format_number(50000), "50,000");
    assert_eq!(token_export::format_number(500000), "500,000");
}
