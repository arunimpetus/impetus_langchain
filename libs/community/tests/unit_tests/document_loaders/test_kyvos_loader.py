from pathlib import Path
from langchain_core.documents import Document
from langchain_community.document_loaders.kyvos_loader import KyvosLoader

import os


class TestKyvosLoader:
    parsed_json = {'login_url': 'https://trial.kyvosinsights.com/kyvos/rest/login',
                   'query_url': 'https://trial.kyvosinsights.com/kyvos/rest/export/query',
                   'query_type': 'SQL',
                   'output_format': 'csv',
                   'line_seperator': '%5Cr%5Cn',
                   'enclosed_by': "'",
                   'connector_type': 'Rest',
                   'zipped': 'false',
                   'include_header': 'true',
                   'kms': 'false',
                   'output_file_name': "sample_data_1.csv",
                   'header_accept': 'application/octet-stream',
                   'maxRows': 1000000}
    limit = 2
    username = 'trialuser1'
    password = 'Welcome@123'
    query = f"SELECT `a ssb technical performance 30b_v2`.`customer id` AS `customer id`, `a ssb technical performance 30b_v2`.`postal code` AS `postal code`, `a ssb technical performance 30b_v2`.`city` AS `city`, `a ssb technical performance 30b_v2`.`country` AS `country` FROM `ssb - manufacturing use case`.`a ssb technical performance 30b_v2` `a ssb technical performance 30b_v2` GROUP BY  `a ssb technical performance 30b_v2`.`customer id`, `a ssb technical performance 30b_v2`.`postal code`, `a ssb technical performance 30b_v2`.`city`, `a ssb technical performance 30b_v2`.`country` LIMIT {limit}"

    # Tests that a CSV file with valid data is loaded successfully.
    def test_kyvos_loader_load_valid_data(self) -> None:
        # Setup
        expected_docs = [Document(page_content="'customer id': '18247','postal code': '380001','city': 'Ahmedabad',"
                                               "'country': 'India'", metadata={'file_name': 'sample_data_1.csv',
                                                                               'row_no': 0}),
                         Document(
                             page_content="'customer id': '24010','postal code': '380001','city': 'Ahmedabad',"
                                          "'country': 'India'",
                             metadata={'file_name': 'sample_data_1.csv', 'row_no': 1})]

        # Exercise
        loader = KyvosLoader(configuration_parameters=parsed_json, query=query, username=username, password=password)
        result = loader.load()

        # Assert
        assert result == expected_docs
