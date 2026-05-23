import pytest
from unittest.mock import MagicMock, patch
import sys

# Mock imports before importing the module
mock_firebase = MagicMock()
sys.modules['firebase_admin'] = mock_firebase
sys.modules['firebase_admin.credentials'] = MagicMock()
sys.modules['firebase_admin.firestore'] = MagicMock()
sys.modules['google.cloud'] = MagicMock()
sys.modules['google.cloud.compute_v1'] = MagicMock()

import sentinel_g

def describe_Sentinel_G_방화벽_규칙_관리():
    
    def describe_create_firewall_rule_함수():
        
        @patch('sentinel_g.db')
        @patch('sentinel_g.compute_v1.FirewallsClient')
        def it_정상적인_IP와_포트가_주어지면_방화벽_규칙을_생성하고_Firestore에_active_상태로_저장한다(mock_compute_client, mock_db):
            mock_db.collection.return_value.document.return_value.set = MagicMock()
            
            result = sentinel_g.create_firewall_rule("192.168.1.1", 8080, 60)
            
            assert result["ipAddr"] == "192.168.1.1"
            assert result["port"] == 8080
            assert result["status"] == "open"
            assert result["expireAt"] > result["createdAt"]
            
            # Verify GCP API call
            mock_client_instance = mock_compute_client.return_value
            mock_client_instance.insert.assert_called_once()
            
            # Verify the VPC network parameter is specified in the Firewall construction
            assert sentinel_g.compute_v1.Firewall.called
            constructor_kwargs = sentinel_g.compute_v1.Firewall.call_args.kwargs
            assert constructor_kwargs.get("network") == "global/networks/default"
            
            # Verify Firestore was called
            mock_db.collection.assert_called_with("firewall_rules")
            mock_db.collection.return_value.document.assert_called_with(result["ruleName"])
            mock_db.collection.return_value.document.return_value.set.assert_called_once_with(result)

        def it_비정상적인_IP_형식이_주어지면_ValueError_예외를_발생시킨다():
            with pytest.raises(ValueError, match="Invalid IP address format"):
                sentinel_g.create_firewall_rule("999.999.999.999", 80, 60)
                
            with pytest.raises(ValueError, match="Invalid IP address format"):
                sentinel_g.create_firewall_rule("invalid-ip", 80, 60)

        @patch('sentinel_g.db')
        @patch('sentinel_g.compute_v1.FirewallsClient')
        def it_GCP_API_호출_실패_시_예외를_발생시키고_Firestore에_저장하지_않는다(mock_compute_client, mock_db):
            # Setup GCP API to raise an exception
            mock_client_instance = mock_compute_client.return_value
            mock_client_instance.insert.side_effect = Exception("API error")
            
            mock_db.collection.return_value.document.return_value.set = MagicMock()
            
            with pytest.raises(RuntimeError, match="GCP API Error: API error"):
                sentinel_g.create_firewall_rule("192.168.1.1", 8080, 60)
                
            # Verify Firestore was NOT called
            mock_db.collection.return_value.document.return_value.set.assert_not_called()

    def describe_update_rule_status_함수():
        @patch('sentinel_g.db')
        def it_상태값을_정상적으로_업데이트한다(mock_db):
            mock_doc = mock_db.collection.return_value.document.return_value
            sentinel_g.update_rule_status("rule-123", "warning")
            mock_db.collection.assert_called_with("firewall_rules")
            mock_db.collection.return_value.document.assert_called_with("rule-123")
            mock_doc.update.assert_called_once_with({"status": "warning"})

    def describe_delete_firewall_rule_함수():
        @patch('sentinel_g.db')
        @patch('sentinel_g.compute_v1.FirewallsClient')
        def it_방화벽을_삭제하고_상태를_closed로_변경한다(mock_compute_client, mock_db):
            mock_doc = mock_db.collection.return_value.document.return_value
            sentinel_g.delete_firewall_rule("rule-123")
            
            mock_doc.update.assert_called_once_with({"status": "closed"})
            mock_client_instance = mock_compute_client.return_value
            mock_client_instance.delete.assert_called_once_with(project="test-project", firewall="rule-123")

    def describe_cleanup_rules_함수():
        
        @patch('sentinel_g.db')
        @patch('sentinel_g.compute_v1.FirewallsClient')
        def it_만료된_규칙을_조회하여_GCP에서_삭제하고_Firestore_상태를_deleted로_변경한다(mock_compute_client, mock_db):
            # Setup mock Firestore query
            mock_doc = MagicMock()
            mock_doc.to_dict.return_value = {"ruleName": "rule-123", "status": "active", "expireAt": 0}
            mock_query = mock_db.collection.return_value.where.return_value
            mock_query.stream.return_value = [mock_doc]
            
            deleted_count = sentinel_g.cleanup_rules()
            
            assert deleted_count == 1
            
            # Verify GCP API delete called
            mock_client_instance = mock_compute_client.return_value
            mock_client_instance.delete.assert_called_once_with(project="test-project", firewall="rule-123")
            
            # Verify Firestore update called
            mock_doc.reference.update.assert_called_once_with({"status": "deleted"})

        @patch('sentinel_g.db')
        @patch('sentinel_g.compute_v1.FirewallsClient')
        def it_만료된_규칙이_없으면_아무_작업도_수행하지_않는다(mock_compute_client, mock_db):
            # Setup empty query
            mock_query = mock_db.collection.return_value.where.return_value
            mock_query.stream.return_value = []
            
            deleted_count = sentinel_g.cleanup_rules()
            
            assert deleted_count == 0
            
            # Verify no GCP API call
            mock_client_instance = mock_compute_client.return_value
            mock_client_instance.delete.assert_not_called()

        @patch('sentinel_g.db')
        @patch('sentinel_g.compute_v1.FirewallsClient')
        def it_GCP_방화벽_삭제가_실패하더라도_다른_규칙_삭제를_계속_진행하고_실패한_항목은_상태를_변경하지_않는다(mock_compute_client, mock_db):
            # Setup two mock documents
            mock_doc1 = MagicMock()
            mock_doc1.to_dict.return_value = {"ruleName": "rule-1", "status": "warning", "expireAt": 0}
            
            mock_doc2 = MagicMock()
            mock_doc2.to_dict.return_value = {"ruleName": "rule-2", "status": "open", "expireAt": 0}
            
            mock_query = mock_db.collection.return_value.where.return_value
            mock_query.stream.return_value = [mock_doc1, mock_doc2]
            
            # Setup GCP API to fail on the first deletion, succeed on the second
            mock_client_instance = mock_compute_client.return_value
            
            def side_effect(*args, **kwargs):
                if kwargs.get('firewall') == 'rule-1':
                    raise Exception("Delete error")
                return MagicMock()
                
            mock_client_instance.delete.side_effect = side_effect
            
            deleted_count = sentinel_g.cleanup_rules()
            
            # Only 1 deleted
            assert deleted_count == 1
            
            # Verify GCP API was called for both
            assert mock_client_instance.delete.call_count == 2
            
            # Verify Firestore update called only for doc2
            mock_doc1.reference.update.assert_not_called()
            mock_doc2.reference.update.assert_called_once_with({"status": "deleted"})
