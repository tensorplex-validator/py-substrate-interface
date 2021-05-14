# Python Substrate Interface Library
#
# Copyright 2018-2020 Stichting Polkascan (Polkascan Foundation).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import requests

from scalecodec import ScaleDecoder
from substrateinterface.plugins import Plugin


class PolkascanPlugin(Plugin):

    supported_filters = ('block_start', 'block_end', 'account_id', 'pallet_name', 'event_name')

    def __init__(self, max_requests=5):
        self.max_requests = max_requests
        super().__init__()

    def filter_events(self, block_start: int = None, block_end: int = None, pallet_name: str = None,
                      event_name: str = None, account_id: str = None):

        # Requirements check
        chain_name = self.substrate.chain.lower()

        filter_result = []

        if chain_name not in ['polkadot', 'kusama', 'rococo']:
            raise ValueError(f'Chain "{self.substrate.chain}" not supported')

        page_number = 0
        request_count = 0
        running = True

        while running and request_count <= self.max_requests:

            base_url = f'https://explorer-32.polkascan.io/api/v1/{chain_name}/event?filter[module_id]={pallet_name.lower()}&' + \
                       f'filter[event_id]={event_name}'

            if account_id is not None:

                base_url += f'&filter[address]={account_id}'

                if pallet_name == 'Staking' and event_name == 'Reward':
                    base_url += '&filter[search_index]=39'
                else:
                    raise NotImplementedError('Filtering on account_id not supported')

            page_number += 1

            result = requests.get(base_url + f'&page[number]={page_number}&page[size]=100')

            if result.status_code != 200:
                raise ValueError('Request to Polkascan failed')

            result_data = result.json()
            for event in result_data['data']:
                # Check block range
                if event['attributes']['block_id'] < block_start:
                    running = False
                    break

                if event['attributes']['block_id'] > block_end:
                    continue

                item = ScaleDecoder.get_decoder_class('EventRecord')

                item.value = {
                    'module_id': event['attributes']['module_id'],
                    'event_id': event['attributes']['event_id'],
                    'params': event['attributes']['attributes']
                }

                filter_result.append(item)

        return filter_result
